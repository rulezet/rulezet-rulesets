rule TTP_XOR_QUAD_CurrentVersionRun_68f8 {
  strings:
    $key_68f8 = { 3b 97 [2] 1f 99 [2] 34 b5 [2] 1a 97 [2] 0e 8c [2] 01 96 [2] 1f 8b [2] 1d 8a [2] 06 8c [2] 1a 8b [2] 06 a4 }

  condition:
    any of them
}