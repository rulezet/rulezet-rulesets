rule TTP_XOR_QUAD_CurrentVersionRun_fef3 {
  strings:
    $key_fef3 = { ad 9c [2] 89 92 [2] a2 be [2] 8c 9c [2] 98 87 [2] 97 9d [2] 89 80 [2] 8b 81 [2] 90 87 [2] 8c 80 [2] 90 af }

  condition:
    any of them
}