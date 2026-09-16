rule TTP_XOR_QUAD_CurrentVersionRun_7484 {
  strings:
    $key_7484 = { 27 eb [2] 03 e5 [2] 28 c9 [2] 06 eb [2] 12 f0 [2] 1d ea [2] 03 f7 [2] 01 f6 [2] 1a f0 [2] 06 f7 [2] 1a d8 }

  condition:
    any of them
}