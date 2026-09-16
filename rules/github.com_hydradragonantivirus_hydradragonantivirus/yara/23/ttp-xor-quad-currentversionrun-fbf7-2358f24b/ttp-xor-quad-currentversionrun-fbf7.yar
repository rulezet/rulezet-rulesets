rule TTP_XOR_QUAD_CurrentVersionRun_fbf7 {
  strings:
    $key_fbf7 = { a8 98 [2] 8c 96 [2] a7 ba [2] 89 98 [2] 9d 83 [2] 92 99 [2] 8c 84 [2] 8e 85 [2] 95 83 [2] 89 84 [2] 95 ab }

  condition:
    any of them
}