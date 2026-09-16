rule TTP_XOR_QUAD_CurrentVersionRun_6184 {
  strings:
    $key_6184 = { 32 eb [2] 16 e5 [2] 3d c9 [2] 13 eb [2] 07 f0 [2] 08 ea [2] 16 f7 [2] 14 f6 [2] 0f f0 [2] 13 f7 [2] 0f d8 }

  condition:
    any of them
}