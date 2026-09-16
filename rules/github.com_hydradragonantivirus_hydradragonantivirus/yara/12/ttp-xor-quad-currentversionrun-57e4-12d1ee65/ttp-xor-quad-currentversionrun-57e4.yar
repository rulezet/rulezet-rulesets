rule TTP_XOR_QUAD_CurrentVersionRun_57e4 {
  strings:
    $key_57e4 = { 04 8b [2] 20 85 [2] 0b a9 [2] 25 8b [2] 31 90 [2] 3e 8a [2] 20 97 [2] 22 96 [2] 39 90 [2] 25 97 [2] 39 b8 }

  condition:
    any of them
}