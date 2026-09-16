rule TTP_XOR_QUAD_CurrentVersionRun_fa25 {
  strings:
    $key_fa25 = { a9 4a [2] 8d 44 [2] a6 68 [2] 88 4a [2] 9c 51 [2] 93 4b [2] 8d 56 [2] 8f 57 [2] 94 51 [2] 88 56 [2] 94 79 }

  condition:
    any of them
}