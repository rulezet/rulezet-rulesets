rule TTP_XOR_QUAD_CurrentVersionRun_318b {
  strings:
    $key_318b = { 62 e4 [2] 46 ea [2] 6d c6 [2] 43 e4 [2] 57 ff [2] 58 e5 [2] 46 f8 [2] 44 f9 [2] 5f ff [2] 43 f8 [2] 5f d7 }

  condition:
    any of them
}