rule TTP_XOR_QUAD_CurrentVersionRun_7cf8 {
  strings:
    $key_7cf8 = { 2f 97 [2] 0b 99 [2] 20 b5 [2] 0e 97 [2] 1a 8c [2] 15 96 [2] 0b 8b [2] 09 8a [2] 12 8c [2] 0e 8b [2] 12 a4 }

  condition:
    any of them
}