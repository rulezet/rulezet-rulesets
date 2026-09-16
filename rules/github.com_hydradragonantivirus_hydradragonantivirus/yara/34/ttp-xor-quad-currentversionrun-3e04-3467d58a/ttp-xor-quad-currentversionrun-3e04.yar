rule TTP_XOR_QUAD_CurrentVersionRun_3e04 {
  strings:
    $key_3e04 = { 6d 6b [2] 49 65 [2] 62 49 [2] 4c 6b [2] 58 70 [2] 57 6a [2] 49 77 [2] 4b 76 [2] 50 70 [2] 4c 77 [2] 50 58 }

  condition:
    any of them
}