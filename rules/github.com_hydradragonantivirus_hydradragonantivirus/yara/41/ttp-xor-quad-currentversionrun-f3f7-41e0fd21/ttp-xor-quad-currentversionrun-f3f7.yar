rule TTP_XOR_QUAD_CurrentVersionRun_f3f7 {
  strings:
    $key_f3f7 = { a0 98 [2] 84 96 [2] af ba [2] 81 98 [2] 95 83 [2] 9a 99 [2] 84 84 [2] 86 85 [2] 9d 83 [2] 81 84 [2] 9d ab }

  condition:
    any of them
}