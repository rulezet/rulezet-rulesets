rule TTP_XOR_QUAD_CurrentVersionRun_68f9 {
  strings:
    $key_68f9 = { 3b 96 [2] 1f 98 [2] 34 b4 [2] 1a 96 [2] 0e 8d [2] 01 97 [2] 1f 8a [2] 1d 8b [2] 06 8d [2] 1a 8a [2] 06 a5 }

  condition:
    any of them
}