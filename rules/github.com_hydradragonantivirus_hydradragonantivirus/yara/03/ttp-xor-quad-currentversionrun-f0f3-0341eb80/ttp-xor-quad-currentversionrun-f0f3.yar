rule TTP_XOR_QUAD_CurrentVersionRun_f0f3 {
  strings:
    $key_f0f3 = { a3 9c [2] 87 92 [2] ac be [2] 82 9c [2] 96 87 [2] 99 9d [2] 87 80 [2] 85 81 [2] 9e 87 [2] 82 80 [2] 9e af }

  condition:
    any of them
}