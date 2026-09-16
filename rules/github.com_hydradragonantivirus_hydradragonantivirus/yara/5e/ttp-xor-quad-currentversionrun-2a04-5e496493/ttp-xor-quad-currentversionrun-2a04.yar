rule TTP_XOR_QUAD_CurrentVersionRun_2a04 {
  strings:
    $key_2a04 = { 79 6b [2] 5d 65 [2] 76 49 [2] 58 6b [2] 4c 70 [2] 43 6a [2] 5d 77 [2] 5f 76 [2] 44 70 [2] 58 77 [2] 44 58 }

  condition:
    any of them
}