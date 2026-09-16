rule TTP_XOR_QUAD_CurrentVersionRun_f51c {
  strings:
    $key_f51c = { a6 73 [2] 82 7d [2] a9 51 [2] 87 73 [2] 93 68 [2] 9c 72 [2] 82 6f [2] 80 6e [2] 9b 68 [2] 87 6f [2] 9b 40 }

  condition:
    any of them
}