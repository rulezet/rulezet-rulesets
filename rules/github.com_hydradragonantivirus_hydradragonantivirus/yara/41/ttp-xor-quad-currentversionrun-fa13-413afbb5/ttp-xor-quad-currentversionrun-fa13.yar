rule TTP_XOR_QUAD_CurrentVersionRun_fa13 {
  strings:
    $key_fa13 = { a9 7c [2] 8d 72 [2] a6 5e [2] 88 7c [2] 9c 67 [2] 93 7d [2] 8d 60 [2] 8f 61 [2] 94 67 [2] 88 60 [2] 94 4f }

  condition:
    any of them
}