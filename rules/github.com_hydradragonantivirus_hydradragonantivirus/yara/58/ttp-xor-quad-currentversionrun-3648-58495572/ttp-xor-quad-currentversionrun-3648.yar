rule TTP_XOR_QUAD_CurrentVersionRun_3648 {
  strings:
    $key_3648 = { 65 27 [2] 41 29 [2] 6a 05 [2] 44 27 [2] 50 3c [2] 5f 26 [2] 41 3b [2] 43 3a [2] 58 3c [2] 44 3b [2] 58 14 }

  condition:
    any of them
}