rule TTP_XOR_QUAD_CurrentVersionRun_e7f1 {
  strings:
    $key_e7f1 = { b4 9e [2] 90 90 [2] bb bc [2] 95 9e [2] 81 85 [2] 8e 9f [2] 90 82 [2] 92 83 [2] 89 85 [2] 95 82 [2] 89 ad }

  condition:
    any of them
}