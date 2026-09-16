rule TTP_XOR_QUAD_CurrentVersionRun_f4f6 {
  strings:
    $key_f4f6 = { a7 99 [2] 83 97 [2] a8 bb [2] 86 99 [2] 92 82 [2] 9d 98 [2] 83 85 [2] 81 84 [2] 9a 82 [2] 86 85 [2] 9a aa }

  condition:
    any of them
}