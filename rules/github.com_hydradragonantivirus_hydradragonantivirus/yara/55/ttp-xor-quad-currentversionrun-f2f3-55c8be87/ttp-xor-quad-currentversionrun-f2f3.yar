rule TTP_XOR_QUAD_CurrentVersionRun_f2f3 {
  strings:
    $key_f2f3 = { a1 9c [2] 85 92 [2] ae be [2] 80 9c [2] 94 87 [2] 9b 9d [2] 85 80 [2] 87 81 [2] 9c 87 [2] 80 80 [2] 9c af }

  condition:
    any of them
}