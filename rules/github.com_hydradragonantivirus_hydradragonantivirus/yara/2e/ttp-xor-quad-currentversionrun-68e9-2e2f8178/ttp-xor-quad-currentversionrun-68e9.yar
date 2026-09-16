rule TTP_XOR_QUAD_CurrentVersionRun_68e9 {
  strings:
    $key_68e9 = { 3b 86 [2] 1f 88 [2] 34 a4 [2] 1a 86 [2] 0e 9d [2] 01 87 [2] 1f 9a [2] 1d 9b [2] 06 9d [2] 1a 9a [2] 06 b5 }

  condition:
    any of them
}