rule TTP_XOR_QUAD_CurrentVersionRun_fbfd {
  strings:
    $key_fbfd = { a8 92 [2] 8c 9c [2] a7 b0 [2] 89 92 [2] 9d 89 [2] 92 93 [2] 8c 8e [2] 8e 8f [2] 95 89 [2] 89 8e [2] 95 a1 }

  condition:
    any of them
}