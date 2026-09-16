rule TTP_XOR_QUAD_CurrentVersionRun_6185 {
  strings:
    $key_6185 = { 32 ea [2] 16 e4 [2] 3d c8 [2] 13 ea [2] 07 f1 [2] 08 eb [2] 16 f6 [2] 14 f7 [2] 0f f1 [2] 13 f6 [2] 0f d9 }

  condition:
    any of them
}