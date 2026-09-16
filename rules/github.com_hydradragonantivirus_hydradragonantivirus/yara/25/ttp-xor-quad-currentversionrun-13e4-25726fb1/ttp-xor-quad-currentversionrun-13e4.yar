rule TTP_XOR_QUAD_CurrentVersionRun_13e4 {
  strings:
    $key_13e4 = { 40 8b [2] 64 85 [2] 4f a9 [2] 61 8b [2] 75 90 [2] 7a 8a [2] 64 97 [2] 66 96 [2] 7d 90 [2] 61 97 [2] 7d b8 }

  condition:
    any of them
}