rule TTP_XOR_QUAD_CurrentVersionRun_f57d {
  strings:
    $key_f57d = { a6 12 [2] 82 1c [2] a9 30 [2] 87 12 [2] 93 09 [2] 9c 13 [2] 82 0e [2] 80 0f [2] 9b 09 [2] 87 0e [2] 9b 21 }

  condition:
    any of them
}