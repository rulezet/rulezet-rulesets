rule TTP_XOR_QUAD_CurrentVersionRun_d9f3 {
  strings:
    $key_d9f3 = { 8a 9c [2] ae 92 [2] 85 be [2] ab 9c [2] bf 87 [2] b0 9d [2] ae 80 [2] ac 81 [2] b7 87 [2] ab 80 [2] b7 af }

  condition:
    any of them
}