rule TTP_XOR_QUAD_CurrentVersionRun_bd97 {
  strings:
    $key_bd97 = { ee f8 [2] ca f6 [2] e1 da [2] cf f8 [2] db e3 [2] d4 f9 [2] ca e4 [2] c8 e5 [2] d3 e3 [2] cf e4 [2] d3 cb }

  condition:
    any of them
}