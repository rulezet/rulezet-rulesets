rule TTP_XOR_QUAD_CurrentVersionRun_3ee4 {
  strings:
    $key_3ee4 = { 6d 8b [2] 49 85 [2] 62 a9 [2] 4c 8b [2] 58 90 [2] 57 8a [2] 49 97 [2] 4b 96 [2] 50 90 [2] 4c 97 [2] 50 b8 }

  condition:
    any of them
}