rule TTP_XOR_QUAD_CurrentVersionRun_efa8 {
  strings:
    $key_efa8 = { bc c7 [2] 98 c9 [2] b3 e5 [2] 9d c7 [2] 89 dc [2] 86 c6 [2] 98 db [2] 9a da [2] 81 dc [2] 9d db [2] 81 f4 }

  condition:
    any of them
}