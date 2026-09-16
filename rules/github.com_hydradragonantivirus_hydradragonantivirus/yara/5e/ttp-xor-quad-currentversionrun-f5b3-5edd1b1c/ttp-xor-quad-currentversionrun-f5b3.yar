rule TTP_XOR_QUAD_CurrentVersionRun_f5b3 {
  strings:
    $key_f5b3 = { a6 dc [2] 82 d2 [2] a9 fe [2] 87 dc [2] 93 c7 [2] 9c dd [2] 82 c0 [2] 80 c1 [2] 9b c7 [2] 87 c0 [2] 9b ef }

  condition:
    any of them
}