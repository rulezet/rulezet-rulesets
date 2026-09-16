rule TTP_XOR_QUAD_CurrentVersionRun_f54f {
  strings:
    $key_f54f = { a6 20 [2] 82 2e [2] a9 02 [2] 87 20 [2] 93 3b [2] 9c 21 [2] 82 3c [2] 80 3d [2] 9b 3b [2] 87 3c [2] 9b 13 }

  condition:
    any of them
}