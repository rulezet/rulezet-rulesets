rule TTP_XOR_QUAD_CurrentVersionRun_fbf6 {
  strings:
    $key_fbf6 = { a8 99 [2] 8c 97 [2] a7 bb [2] 89 99 [2] 9d 82 [2] 92 98 [2] 8c 85 [2] 8e 84 [2] 95 82 [2] 89 85 [2] 95 aa }

  condition:
    any of them
}