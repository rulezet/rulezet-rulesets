rule TTP_XOR_QUAD_CurrentVersionRun_fbf1 {
  strings:
    $key_fbf1 = { a8 9e [2] 8c 90 [2] a7 bc [2] 89 9e [2] 9d 85 [2] 92 9f [2] 8c 82 [2] 8e 83 [2] 95 85 [2] 89 82 [2] 95 ad }

  condition:
    any of them
}