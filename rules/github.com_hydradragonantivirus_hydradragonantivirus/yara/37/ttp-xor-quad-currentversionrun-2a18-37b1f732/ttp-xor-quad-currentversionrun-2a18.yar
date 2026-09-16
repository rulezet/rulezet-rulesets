rule TTP_XOR_QUAD_CurrentVersionRun_2a18 {
  strings:
    $key_2a18 = { 79 77 [2] 5d 79 [2] 76 55 [2] 58 77 [2] 4c 6c [2] 43 76 [2] 5d 6b [2] 5f 6a [2] 44 6c [2] 58 6b [2] 44 44 }

  condition:
    any of them
}