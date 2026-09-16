rule TTP_XOR_QUAD_CurrentVersionRun_f6f3 {
  strings:
    $key_f6f3 = { a5 9c [2] 81 92 [2] aa be [2] 84 9c [2] 90 87 [2] 9f 9d [2] 81 80 [2] 83 81 [2] 98 87 [2] 84 80 [2] 98 af }

  condition:
    any of them
}