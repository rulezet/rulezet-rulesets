rule TTP_XOR_QUAD_CurrentVersionRun_2f04 {
  strings:
    $key_2f04 = { 7c 6b [2] 58 65 [2] 73 49 [2] 5d 6b [2] 49 70 [2] 46 6a [2] 58 77 [2] 5a 76 [2] 41 70 [2] 5d 77 [2] 41 58 }

  condition:
    any of them
}