rule TTP_XOR_QUAD_CurrentVersionRun_f52f {
  strings:
    $key_f52f = { a6 40 [2] 82 4e [2] a9 62 [2] 87 40 [2] 93 5b [2] 9c 41 [2] 82 5c [2] 80 5d [2] 9b 5b [2] 87 5c [2] 9b 73 }

  condition:
    any of them
}