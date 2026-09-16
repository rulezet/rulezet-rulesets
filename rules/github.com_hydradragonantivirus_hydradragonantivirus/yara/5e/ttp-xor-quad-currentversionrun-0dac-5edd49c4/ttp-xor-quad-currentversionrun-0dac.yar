rule TTP_XOR_QUAD_CurrentVersionRun_0dac {
  strings:
    $key_0dac = { 5e c3 [2] 7a cd [2] 51 e1 [2] 7f c3 [2] 6b d8 [2] 64 c2 [2] 7a df [2] 78 de [2] 63 d8 [2] 7f df [2] 63 f0 }

  condition:
    any of them
}