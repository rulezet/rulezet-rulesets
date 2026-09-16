rule TTP_XOR_QUAD_CurrentVersionRun_1d78 {
  strings:
    $key_1d78 = { 4e 17 [2] 6a 19 [2] 41 35 [2] 6f 17 [2] 7b 0c [2] 74 16 [2] 6a 0b [2] 68 0a [2] 73 0c [2] 6f 0b [2] 73 24 }

  condition:
    any of them
}