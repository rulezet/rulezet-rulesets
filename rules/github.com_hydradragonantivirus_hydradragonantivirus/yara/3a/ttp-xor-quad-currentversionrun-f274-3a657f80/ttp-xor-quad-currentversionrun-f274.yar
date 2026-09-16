rule TTP_XOR_QUAD_CurrentVersionRun_f274 {
  strings:
    $key_f274 = { a1 1b [2] 85 15 [2] ae 39 [2] 80 1b [2] 94 00 [2] 9b 1a [2] 85 07 [2] 87 06 [2] 9c 00 [2] 80 07 [2] 9c 28 }

  condition:
    any of them
}