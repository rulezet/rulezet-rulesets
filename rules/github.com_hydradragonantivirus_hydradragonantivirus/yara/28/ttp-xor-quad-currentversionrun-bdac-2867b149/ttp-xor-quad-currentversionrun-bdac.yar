rule TTP_XOR_QUAD_CurrentVersionRun_bdac {
  strings:
    $key_bdac = { ee c3 [2] ca cd [2] e1 e1 [2] cf c3 [2] db d8 [2] d4 c2 [2] ca df [2] c8 de [2] d3 d8 [2] cf df [2] d3 f0 }

  condition:
    any of them
}