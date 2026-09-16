rule TTP_XOR_QUAD_CurrentVersionRun_faf3 {
  strings:
    $key_faf3 = { a9 9c [2] 8d 92 [2] a6 be [2] 88 9c [2] 9c 87 [2] 93 9d [2] 8d 80 [2] 8f 81 [2] 94 87 [2] 88 80 [2] 94 af }

  condition:
    any of them
}