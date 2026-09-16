rule TTP_XOR_QUAD_CurrentVersionRun_fa77 {
  strings:
    $key_fa77 = { a9 18 [2] 8d 16 [2] a6 3a [2] 88 18 [2] 9c 03 [2] 93 19 [2] 8d 04 [2] 8f 05 [2] 94 03 [2] 88 04 [2] 94 2b }

  condition:
    any of them
}