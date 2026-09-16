rule TTP_XOR_QUAD_CurrentVersionRun_faf8 {
  strings:
    $key_faf8 = { a9 97 [2] 8d 99 [2] a6 b5 [2] 88 97 [2] 9c 8c [2] 93 96 [2] 8d 8b [2] 8f 8a [2] 94 8c [2] 88 8b [2] 94 a4 }

  condition:
    any of them
}