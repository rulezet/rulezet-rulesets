rule TTP_XOR_QUAD_CurrentVersionRun_4665 {
  strings:
    $key_4665 = { 15 0a [2] 31 04 [2] 1a 28 [2] 34 0a [2] 20 11 [2] 2f 0b [2] 31 16 [2] 33 17 [2] 28 11 [2] 34 16 [2] 28 39 }

  condition:
    any of them
}