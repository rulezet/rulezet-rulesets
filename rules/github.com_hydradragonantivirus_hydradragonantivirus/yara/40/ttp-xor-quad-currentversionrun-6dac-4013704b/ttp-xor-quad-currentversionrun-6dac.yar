rule TTP_XOR_QUAD_CurrentVersionRun_6dac {
  strings:
    $key_6dac = { 3e c3 [2] 1a cd [2] 31 e1 [2] 1f c3 [2] 0b d8 [2] 04 c2 [2] 1a df [2] 18 de [2] 03 d8 [2] 1f df [2] 03 f0 }

  condition:
    any of them
}