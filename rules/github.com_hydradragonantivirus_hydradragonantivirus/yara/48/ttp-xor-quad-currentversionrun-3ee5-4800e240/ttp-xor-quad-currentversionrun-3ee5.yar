rule TTP_XOR_QUAD_CurrentVersionRun_3ee5 {
  strings:
    $key_3ee5 = { 6d 8a [2] 49 84 [2] 62 a8 [2] 4c 8a [2] 58 91 [2] 57 8b [2] 49 96 [2] 4b 97 [2] 50 91 [2] 4c 96 [2] 50 b9 }

  condition:
    any of them
}