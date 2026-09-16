rule TTP_XOR_QUAD_CurrentVersionRun_f5f7 {
  strings:
    $key_f5f7 = { a6 98 [2] 82 96 [2] a9 ba [2] 87 98 [2] 93 83 [2] 9c 99 [2] 82 84 [2] 80 85 [2] 9b 83 [2] 87 84 [2] 9b ab }

  condition:
    any of them
}