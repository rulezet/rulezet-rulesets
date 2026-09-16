rule TTP_XOR_QUAD_CurrentVersionRun_f5f6 {
  strings:
    $key_f5f6 = { a6 99 [2] 82 97 [2] a9 bb [2] 87 99 [2] 93 82 [2] 9c 98 [2] 82 85 [2] 80 84 [2] 9b 82 [2] 87 85 [2] 9b aa }

  condition:
    any of them
}