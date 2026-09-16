rule TTP_XOR_QUAD_CurrentVersionRun_1cf9 {
  strings:
    $key_1cf9 = { 4f 96 [2] 6b 98 [2] 40 b4 [2] 6e 96 [2] 7a 8d [2] 75 97 [2] 6b 8a [2] 69 8b [2] 72 8d [2] 6e 8a [2] 72 a5 }

  condition:
    any of them
}