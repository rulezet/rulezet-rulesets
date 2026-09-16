rule TTP_XOR_QUAD_CurrentVersionRun_fbee {
  strings:
    $key_fbee = { a8 81 [2] 8c 8f [2] a7 a3 [2] 89 81 [2] 9d 9a [2] 92 80 [2] 8c 9d [2] 8e 9c [2] 95 9a [2] 89 9d [2] 95 b2 }

  condition:
    any of them
}