rule TTP_XOR_QUAD_CurrentVersionRun_1cf8 {
  strings:
    $key_1cf8 = { 4f 97 [2] 6b 99 [2] 40 b5 [2] 6e 97 [2] 7a 8c [2] 75 96 [2] 6b 8b [2] 69 8a [2] 72 8c [2] 6e 8b [2] 72 a4 }

  condition:
    any of them
}