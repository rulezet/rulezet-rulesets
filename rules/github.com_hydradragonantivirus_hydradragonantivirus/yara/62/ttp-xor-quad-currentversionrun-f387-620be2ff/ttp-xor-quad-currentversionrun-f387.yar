rule TTP_XOR_QUAD_CurrentVersionRun_f387 {
  strings:
    $key_f387 = { a0 e8 [2] 84 e6 [2] af ca [2] 81 e8 [2] 95 f3 [2] 9a e9 [2] 84 f4 [2] 86 f5 [2] 9d f3 [2] 81 f4 [2] 9d db }

  condition:
    any of them
}