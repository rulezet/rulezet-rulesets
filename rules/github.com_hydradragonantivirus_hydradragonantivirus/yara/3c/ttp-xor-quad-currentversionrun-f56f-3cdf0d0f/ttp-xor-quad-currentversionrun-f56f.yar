rule TTP_XOR_QUAD_CurrentVersionRun_f56f {
  strings:
    $key_f56f = { a6 00 [2] 82 0e [2] a9 22 [2] 87 00 [2] 93 1b [2] 9c 01 [2] 82 1c [2] 80 1d [2] 9b 1b [2] 87 1c [2] 9b 33 }

  condition:
    any of them
}