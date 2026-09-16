rule TTP_XOR_QUAD_CurrentVersionRun_0b55 {
  strings:
    $key_0b55 = { 58 3a [2] 7c 34 [2] 57 18 [2] 79 3a [2] 6d 21 [2] 62 3b [2] 7c 26 [2] 7e 27 [2] 65 21 [2] 79 26 [2] 65 09 }

  condition:
    any of them
}