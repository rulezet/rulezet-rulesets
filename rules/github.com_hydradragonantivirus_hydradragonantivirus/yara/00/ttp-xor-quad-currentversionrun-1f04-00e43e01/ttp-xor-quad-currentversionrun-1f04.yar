rule TTP_XOR_QUAD_CurrentVersionRun_1f04 {
  strings:
    $key_1f04 = { 4c 6b [2] 68 65 [2] 43 49 [2] 6d 6b [2] 79 70 [2] 76 6a [2] 68 77 [2] 6a 76 [2] 71 70 [2] 6d 77 [2] 71 58 }

  condition:
    any of them
}