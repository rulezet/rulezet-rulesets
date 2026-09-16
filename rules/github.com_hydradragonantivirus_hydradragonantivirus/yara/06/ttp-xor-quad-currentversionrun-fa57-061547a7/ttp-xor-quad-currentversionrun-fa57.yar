rule TTP_XOR_QUAD_CurrentVersionRun_fa57 {
  strings:
    $key_fa57 = { a9 38 [2] 8d 36 [2] a6 1a [2] 88 38 [2] 9c 23 [2] 93 39 [2] 8d 24 [2] 8f 25 [2] 94 23 [2] 88 24 [2] 94 0b }

  condition:
    any of them
}