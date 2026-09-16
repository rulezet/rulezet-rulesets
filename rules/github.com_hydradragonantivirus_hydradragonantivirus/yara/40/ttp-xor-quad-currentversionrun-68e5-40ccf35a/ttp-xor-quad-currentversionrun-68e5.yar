rule TTP_XOR_QUAD_CurrentVersionRun_68e5 {
  strings:
    $key_68e5 = { 3b 8a [2] 1f 84 [2] 34 a8 [2] 1a 8a [2] 0e 91 [2] 01 8b [2] 1f 96 [2] 1d 97 [2] 06 91 [2] 1a 96 [2] 06 b9 }

  condition:
    any of them
}