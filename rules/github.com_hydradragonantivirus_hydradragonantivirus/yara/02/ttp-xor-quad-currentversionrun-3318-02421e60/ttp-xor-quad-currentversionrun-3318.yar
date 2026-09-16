rule TTP_XOR_QUAD_CurrentVersionRun_3318 {
  strings:
    $key_3318 = { 60 77 [2] 44 79 [2] 6f 55 [2] 41 77 [2] 55 6c [2] 5a 76 [2] 44 6b [2] 46 6a [2] 5d 6c [2] 41 6b [2] 5d 44 }

  condition:
    any of them
}