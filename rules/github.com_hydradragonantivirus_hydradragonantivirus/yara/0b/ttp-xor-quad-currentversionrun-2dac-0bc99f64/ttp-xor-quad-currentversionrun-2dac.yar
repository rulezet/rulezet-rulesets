rule TTP_XOR_QUAD_CurrentVersionRun_2dac {
  strings:
    $key_2dac = { 7e c3 [2] 5a cd [2] 71 e1 [2] 5f c3 [2] 4b d8 [2] 44 c2 [2] 5a df [2] 58 de [2] 43 d8 [2] 5f df [2] 43 f0 }

  condition:
    any of them
}