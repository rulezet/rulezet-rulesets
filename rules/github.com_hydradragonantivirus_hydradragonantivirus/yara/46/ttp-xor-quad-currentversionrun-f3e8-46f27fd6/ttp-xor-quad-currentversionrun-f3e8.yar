rule TTP_XOR_QUAD_CurrentVersionRun_f3e8 {
  strings:
    $key_f3e8 = { a0 87 [2] 84 89 [2] af a5 [2] 81 87 [2] 95 9c [2] 9a 86 [2] 84 9b [2] 86 9a [2] 9d 9c [2] 81 9b [2] 9d b4 }

  condition:
    any of them
}