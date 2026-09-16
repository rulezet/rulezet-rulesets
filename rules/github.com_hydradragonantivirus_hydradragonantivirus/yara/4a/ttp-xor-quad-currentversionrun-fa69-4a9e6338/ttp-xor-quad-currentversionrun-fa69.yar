rule TTP_XOR_QUAD_CurrentVersionRun_fa69 {
  strings:
    $key_fa69 = { a9 06 [2] 8d 08 [2] a6 24 [2] 88 06 [2] 9c 1d [2] 93 07 [2] 8d 1a [2] 8f 1b [2] 94 1d [2] 88 1a [2] 94 35 }

  condition:
    any of them
}