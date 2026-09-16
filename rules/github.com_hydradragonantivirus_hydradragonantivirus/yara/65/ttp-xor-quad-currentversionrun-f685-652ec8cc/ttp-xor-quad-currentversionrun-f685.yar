rule TTP_XOR_QUAD_CurrentVersionRun_f685 {
  strings:
    $key_f685 = { a5 ea [2] 81 e4 [2] aa c8 [2] 84 ea [2] 90 f1 [2] 9f eb [2] 81 f6 [2] 83 f7 [2] 98 f1 [2] 84 f6 [2] 98 d9 }

  condition:
    any of them
}