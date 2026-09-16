rule TTP_XOR_QUAD_CurrentVersionRun_f56d {
  strings:
    $key_f56d = { a6 02 [2] 82 0c [2] a9 20 [2] 87 02 [2] 93 19 [2] 9c 03 [2] 82 1e [2] 80 1f [2] 9b 19 [2] 87 1e [2] 9b 31 }

  condition:
    any of them
}