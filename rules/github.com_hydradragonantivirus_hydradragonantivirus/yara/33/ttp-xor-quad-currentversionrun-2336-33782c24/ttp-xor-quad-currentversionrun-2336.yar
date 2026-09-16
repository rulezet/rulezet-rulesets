rule TTP_XOR_QUAD_CurrentVersionRun_2336 {
  strings:
    $key_2336 = { 70 59 [2] 54 57 [2] 7f 7b [2] 51 59 [2] 45 42 [2] 4a 58 [2] 54 45 [2] 56 44 [2] 4d 42 [2] 51 45 [2] 4d 6a }

  condition:
    any of them
}