rule TTP_XOR_QUAD_CurrentVersionRun_f9f3 {
  strings:
    $key_f9f3 = { aa 9c [2] 8e 92 [2] a5 be [2] 8b 9c [2] 9f 87 [2] 90 9d [2] 8e 80 [2] 8c 81 [2] 97 87 [2] 8b 80 [2] 97 af }

  condition:
    any of them
}