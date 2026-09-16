rule TTP_XOR_QUAD_CurrentVersionRun_f53c {
  strings:
    $key_f53c = { a6 53 [2] 82 5d [2] a9 71 [2] 87 53 [2] 93 48 [2] 9c 52 [2] 82 4f [2] 80 4e [2] 9b 48 [2] 87 4f [2] 9b 60 }

  condition:
    any of them
}