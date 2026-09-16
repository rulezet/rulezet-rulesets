rule TTP_XOR_QUAD_CurrentVersionRun_74ac {
  strings:
    $key_74ac = { 27 c3 [2] 03 cd [2] 28 e1 [2] 06 c3 [2] 12 d8 [2] 1d c2 [2] 03 df [2] 01 de [2] 1a d8 [2] 06 df [2] 1a f0 }

  condition:
    any of them
}