rule TTP_XOR_QUAD_CurrentVersionRun_58f3 {
  strings:
    $key_58f3 = { 0b 9c [2] 2f 92 [2] 04 be [2] 2a 9c [2] 3e 87 [2] 31 9d [2] 2f 80 [2] 2d 81 [2] 36 87 [2] 2a 80 [2] 36 af }

  condition:
    any of them
}