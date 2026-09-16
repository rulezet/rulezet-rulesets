rule TTP_XOR_QUAD_CurrentVersionRun_f3f3 {
  strings:
    $key_f3f3 = { a0 9c [2] 84 92 [2] af be [2] 81 9c [2] 95 87 [2] 9a 9d [2] 84 80 [2] 86 81 [2] 9d 87 [2] 81 80 [2] 9d af }

  condition:
    any of them
}