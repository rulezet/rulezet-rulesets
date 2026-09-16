rule TTP_XOR_QUAD_CurrentVersionRun_fa1d {
  strings:
    $key_fa1d = { a9 72 [2] 8d 7c [2] a6 50 [2] 88 72 [2] 9c 69 [2] 93 73 [2] 8d 6e [2] 8f 6f [2] 94 69 [2] 88 6e [2] 94 41 }

  condition:
    any of them
}