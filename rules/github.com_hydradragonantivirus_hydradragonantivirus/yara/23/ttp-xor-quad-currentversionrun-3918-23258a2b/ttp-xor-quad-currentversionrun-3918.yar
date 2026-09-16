rule TTP_XOR_QUAD_CurrentVersionRun_3918 {
  strings:
    $key_3918 = { 6a 77 [2] 4e 79 [2] 65 55 [2] 4b 77 [2] 5f 6c [2] 50 76 [2] 4e 6b [2] 4c 6a [2] 57 6c [2] 4b 6b [2] 57 44 }

  condition:
    any of them
}