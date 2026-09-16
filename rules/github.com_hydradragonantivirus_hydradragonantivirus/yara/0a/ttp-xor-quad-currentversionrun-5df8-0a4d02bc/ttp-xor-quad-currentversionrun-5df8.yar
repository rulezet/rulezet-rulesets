rule TTP_XOR_QUAD_CurrentVersionRun_5df8 {
  strings:
    $key_5df8 = { 0e 97 [2] 2a 99 [2] 01 b5 [2] 2f 97 [2] 3b 8c [2] 34 96 [2] 2a 8b [2] 28 8a [2] 33 8c [2] 2f 8b [2] 33 a4 }

  condition:
    any of them
}