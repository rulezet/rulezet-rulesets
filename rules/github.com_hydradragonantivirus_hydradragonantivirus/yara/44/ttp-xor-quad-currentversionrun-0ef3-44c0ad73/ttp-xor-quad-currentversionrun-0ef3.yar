rule TTP_XOR_QUAD_CurrentVersionRun_0ef3 {
  strings:
    $key_0ef3 = { 5d 9c [2] 79 92 [2] 52 be [2] 7c 9c [2] 68 87 [2] 67 9d [2] 79 80 [2] 7b 81 [2] 60 87 [2] 7c 80 [2] 60 af }

  condition:
    any of them
}