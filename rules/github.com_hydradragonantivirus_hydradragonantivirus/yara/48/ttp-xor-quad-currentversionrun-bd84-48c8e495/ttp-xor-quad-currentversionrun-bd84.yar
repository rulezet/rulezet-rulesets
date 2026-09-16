rule TTP_XOR_QUAD_CurrentVersionRun_bd84 {
  strings:
    $key_bd84 = { ee eb [2] ca e5 [2] e1 c9 [2] cf eb [2] db f0 [2] d4 ea [2] ca f7 [2] c8 f6 [2] d3 f0 [2] cf f7 [2] d3 d8 }

  condition:
    any of them
}