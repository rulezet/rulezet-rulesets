rule TTP_XOR_QUAD_CurrentVersionRun_fbed {
  strings:
    $key_fbed = { a8 82 [2] 8c 8c [2] a7 a0 [2] 89 82 [2] 9d 99 [2] 92 83 [2] 8c 9e [2] 8e 9f [2] 95 99 [2] 89 9e [2] 95 b1 }

  condition:
    any of them
}