rule TTP_XOR_QUAD_CurrentVersionRun_f53e {
  strings:
    $key_f53e = { a6 51 [2] 82 5f [2] a9 73 [2] 87 51 [2] 93 4a [2] 9c 50 [2] 82 4d [2] 80 4c [2] 9b 4a [2] 87 4d [2] 9b 62 }

  condition:
    any of them
}