rule TTP_XOR_QUAD_CurrentVersionRun_6684 {
  strings:
    $key_6684 = { 35 eb [2] 11 e5 [2] 3a c9 [2] 14 eb [2] 00 f0 [2] 0f ea [2] 11 f7 [2] 13 f6 [2] 08 f0 [2] 14 f7 [2] 08 d8 }

  condition:
    any of them
}