rule TTP_XOR_QUAD_CurrentVersionRun_fa7b {
  strings:
    $key_fa7b = { a9 14 [2] 8d 1a [2] a6 36 [2] 88 14 [2] 9c 0f [2] 93 15 [2] 8d 08 [2] 8f 09 [2] 94 0f [2] 88 08 [2] 94 27 }

  condition:
    any of them
}