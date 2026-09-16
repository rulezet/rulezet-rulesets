rule TTP_XOR_QUAD_CurrentVersionRun_fa72 {
  strings:
    $key_fa72 = { a9 1d [2] 8d 13 [2] a6 3f [2] 88 1d [2] 9c 06 [2] 93 1c [2] 8d 01 [2] 8f 00 [2] 94 06 [2] 88 01 [2] 94 2e }

  condition:
    any of them
}