rule TTP_XOR_QUAD_CurrentVersionRun_f4f3 {
  strings:
    $key_f4f3 = { a7 9c [2] 83 92 [2] a8 be [2] 86 9c [2] 92 87 [2] 9d 9d [2] 83 80 [2] 81 81 [2] 9a 87 [2] 86 80 [2] 9a af }

  condition:
    any of them
}