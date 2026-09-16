rule TTP_XOR_QUAD_CurrentVersionRun_e2f3 {
  strings:
    $key_e2f3 = { b1 9c [2] 95 92 [2] be be [2] 90 9c [2] 84 87 [2] 8b 9d [2] 95 80 [2] 97 81 [2] 8c 87 [2] 90 80 [2] 8c af }

  condition:
    any of them
}