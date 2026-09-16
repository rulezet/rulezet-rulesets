rule TTP_XOR_QUAD_CurrentVersionRun_4ef3 {
  strings:
    $key_4ef3 = { 1d 9c [2] 39 92 [2] 12 be [2] 3c 9c [2] 28 87 [2] 27 9d [2] 39 80 [2] 3b 81 [2] 20 87 [2] 3c 80 [2] 20 af }

  condition:
    any of them
}