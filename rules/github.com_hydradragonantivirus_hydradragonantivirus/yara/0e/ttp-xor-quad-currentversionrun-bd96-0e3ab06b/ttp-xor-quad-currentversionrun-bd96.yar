rule TTP_XOR_QUAD_CurrentVersionRun_bd96 {
  strings:
    $key_bd96 = { ee f9 [2] ca f7 [2] e1 db [2] cf f9 [2] db e2 [2] d4 f8 [2] ca e5 [2] c8 e4 [2] d3 e2 [2] cf e5 [2] d3 ca }

  condition:
    any of them
}