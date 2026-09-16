rule TTP_XOR_QUAD_CurrentVersionRun_0918 {
  strings:
    $key_0918 = { 5a 77 [2] 7e 79 [2] 55 55 [2] 7b 77 [2] 6f 6c [2] 60 76 [2] 7e 6b [2] 7c 6a [2] 67 6c [2] 7b 6b [2] 67 44 }

  condition:
    any of them
}