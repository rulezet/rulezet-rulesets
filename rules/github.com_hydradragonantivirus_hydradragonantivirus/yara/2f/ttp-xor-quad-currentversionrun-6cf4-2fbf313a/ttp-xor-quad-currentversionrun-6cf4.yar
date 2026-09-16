rule TTP_XOR_QUAD_CurrentVersionRun_6cf4 {
  strings:
    $key_6cf4 = { 3f 9b [2] 1b 95 [2] 30 b9 [2] 1e 9b [2] 0a 80 [2] 05 9a [2] 1b 87 [2] 19 86 [2] 02 80 [2] 1e 87 [2] 02 a8 }

  condition:
    any of them
}