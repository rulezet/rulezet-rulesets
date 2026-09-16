rule TTP_XOR_QUAD_CurrentVersionRun_4918 {
  strings:
    $key_4918 = { 1a 77 [2] 3e 79 [2] 15 55 [2] 3b 77 [2] 2f 6c [2] 20 76 [2] 3e 6b [2] 3c 6a [2] 27 6c [2] 3b 6b [2] 27 44 }

  condition:
    any of them
}