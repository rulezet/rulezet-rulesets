rule TTP_XOR_QUAD_CurrentVersionRun_4dac {
  strings:
    $key_4dac = { 1e c3 [2] 3a cd [2] 11 e1 [2] 3f c3 [2] 2b d8 [2] 24 c2 [2] 3a df [2] 38 de [2] 23 d8 [2] 3f df [2] 23 f0 }

  condition:
    any of them
}