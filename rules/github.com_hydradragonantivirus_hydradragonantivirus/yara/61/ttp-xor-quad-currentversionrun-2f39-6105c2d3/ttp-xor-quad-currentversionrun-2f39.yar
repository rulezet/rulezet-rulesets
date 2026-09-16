rule TTP_XOR_QUAD_CurrentVersionRun_2f39 {
  strings:
    $key_2f39 = { 7c 56 [2] 58 58 [2] 73 74 [2] 5d 56 [2] 49 4d [2] 46 57 [2] 58 4a [2] 5a 4b [2] 41 4d [2] 5d 4a [2] 41 65 }

  condition:
    any of them
}