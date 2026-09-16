rule TTP_XOR_QUAD_CurrentVersionRun_1cf3 {
  strings:
    $key_1cf3 = { 4f 9c [2] 6b 92 [2] 40 be [2] 6e 9c [2] 7a 87 [2] 75 9d [2] 6b 80 [2] 69 81 [2] 72 87 [2] 6e 80 [2] 72 af }

  condition:
    any of them
}