rule TTP_XOR_QUAD_CurrentVersionRun_37e4 {
  strings:
    $key_37e4 = { 64 8b [2] 40 85 [2] 6b a9 [2] 45 8b [2] 51 90 [2] 5e 8a [2] 40 97 [2] 42 96 [2] 59 90 [2] 45 97 [2] 59 b8 }

  condition:
    any of them
}