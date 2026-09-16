rule TTP_XOR_QUAD_CurrentVersionRun_1df3 {
  strings:
    $key_1df3 = { 4e 9c [2] 6a 92 [2] 41 be [2] 6f 9c [2] 7b 87 [2] 74 9d [2] 6a 80 [2] 68 81 [2] 73 87 [2] 6f 80 [2] 73 af }

  condition:
    any of them
}