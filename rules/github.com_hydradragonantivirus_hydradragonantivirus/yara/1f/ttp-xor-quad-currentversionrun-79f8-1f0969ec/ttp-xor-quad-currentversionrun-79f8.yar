rule TTP_XOR_QUAD_CurrentVersionRun_79f8 {
  strings:
    $key_79f8 = { 2a 97 [2] 0e 99 [2] 25 b5 [2] 0b 97 [2] 1f 8c [2] 10 96 [2] 0e 8b [2] 0c 8a [2] 17 8c [2] 0b 8b [2] 17 a4 }

  condition:
    any of them
}