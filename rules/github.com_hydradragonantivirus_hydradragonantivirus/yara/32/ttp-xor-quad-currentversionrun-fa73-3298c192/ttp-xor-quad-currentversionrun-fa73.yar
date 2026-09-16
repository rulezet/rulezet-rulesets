rule TTP_XOR_QUAD_CurrentVersionRun_fa73 {
  strings:
    $key_fa73 = { a9 1c [2] 8d 12 [2] a6 3e [2] 88 1c [2] 9c 07 [2] 93 1d [2] 8d 00 [2] 8f 01 [2] 94 07 [2] 88 00 [2] 94 2f }

  condition:
    any of them
}