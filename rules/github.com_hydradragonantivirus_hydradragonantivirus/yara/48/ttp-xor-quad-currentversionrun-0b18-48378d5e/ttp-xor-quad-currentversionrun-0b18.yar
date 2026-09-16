rule TTP_XOR_QUAD_CurrentVersionRun_0b18 {
  strings:
    $key_0b18 = { 58 77 [2] 7c 79 [2] 57 55 [2] 79 77 [2] 6d 6c [2] 62 76 [2] 7c 6b [2] 7e 6a [2] 65 6c [2] 79 6b [2] 65 44 }

  condition:
    any of them
}