rule TTP_XOR_QUAD_CurrentVersionRun_7ef3 {
  strings:
    $key_7ef3 = { 2d 9c [2] 09 92 [2] 22 be [2] 0c 9c [2] 18 87 [2] 17 9d [2] 09 80 [2] 0b 81 [2] 10 87 [2] 0c 80 [2] 10 af }

  condition:
    any of them
}