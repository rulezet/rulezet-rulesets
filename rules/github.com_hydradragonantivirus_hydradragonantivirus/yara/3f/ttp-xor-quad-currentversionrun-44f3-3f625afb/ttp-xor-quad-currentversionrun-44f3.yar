rule TTP_XOR_QUAD_CurrentVersionRun_44f3 {
  strings:
    $key_44f3 = { 17 9c [2] 33 92 [2] 18 be [2] 36 9c [2] 22 87 [2] 2d 9d [2] 33 80 [2] 31 81 [2] 2a 87 [2] 36 80 [2] 2a af }

  condition:
    any of them
}