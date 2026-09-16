rule TTP_XOR_QUAD_CurrentVersionRun_668b {
  strings:
    $key_668b = { 35 e4 [2] 11 ea [2] 3a c6 [2] 14 e4 [2] 00 ff [2] 0f e5 [2] 11 f8 [2] 13 f9 [2] 08 ff [2] 14 f8 [2] 08 d7 }

  condition:
    any of them
}