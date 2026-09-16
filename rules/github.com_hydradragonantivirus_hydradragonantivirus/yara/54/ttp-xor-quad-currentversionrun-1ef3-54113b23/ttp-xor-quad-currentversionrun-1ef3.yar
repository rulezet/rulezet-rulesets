rule TTP_XOR_QUAD_CurrentVersionRun_1ef3 {
  strings:
    $key_1ef3 = { 4d 9c [2] 69 92 [2] 42 be [2] 6c 9c [2] 78 87 [2] 77 9d [2] 69 80 [2] 6b 81 [2] 70 87 [2] 6c 80 [2] 70 af }

  condition:
    any of them
}