rule TTP_XOR_QUAD_CurrentVersionRun_3dac {
  strings:
    $key_3dac = { 6e c3 [2] 4a cd [2] 61 e1 [2] 4f c3 [2] 5b d8 [2] 54 c2 [2] 4a df [2] 48 de [2] 53 d8 [2] 4f df [2] 53 f0 }

  condition:
    any of them
}