rule TTP_XOR_QUAD_CurrentVersionRun_f3b4 {
  strings:
    $key_f3b4 = { a0 db [2] 84 d5 [2] af f9 [2] 81 db [2] 95 c0 [2] 9a da [2] 84 c7 [2] 86 c6 [2] 9d c0 [2] 81 c7 [2] 9d e8 }

  condition:
    any of them
}