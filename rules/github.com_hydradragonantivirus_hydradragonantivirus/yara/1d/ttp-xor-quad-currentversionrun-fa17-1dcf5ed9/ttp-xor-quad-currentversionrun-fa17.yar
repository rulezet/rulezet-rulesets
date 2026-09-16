rule TTP_XOR_QUAD_CurrentVersionRun_fa17 {
  strings:
    $key_fa17 = { a9 78 [2] 8d 76 [2] a6 5a [2] 88 78 [2] 9c 63 [2] 93 79 [2] 8d 64 [2] 8f 65 [2] 94 63 [2] 88 64 [2] 94 4b }

  condition:
    any of them
}