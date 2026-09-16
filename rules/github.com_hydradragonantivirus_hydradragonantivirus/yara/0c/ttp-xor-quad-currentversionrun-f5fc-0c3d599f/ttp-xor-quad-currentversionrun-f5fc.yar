rule TTP_XOR_QUAD_CurrentVersionRun_f5fc {
  strings:
    $key_f5fc = { a6 93 [2] 82 9d [2] a9 b1 [2] 87 93 [2] 93 88 [2] 9c 92 [2] 82 8f [2] 80 8e [2] 9b 88 [2] 87 8f [2] 9b a0 }

  condition:
    any of them
}