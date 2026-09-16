rule TTP_XOR_QUAD_CurrentVersionRun_fa1b {
  strings:
    $key_fa1b = { a9 74 [2] 8d 7a [2] a6 56 [2] 88 74 [2] 9c 6f [2] 93 75 [2] 8d 68 [2] 8f 69 [2] 94 6f [2] 88 68 [2] 94 47 }

  condition:
    any of them
}