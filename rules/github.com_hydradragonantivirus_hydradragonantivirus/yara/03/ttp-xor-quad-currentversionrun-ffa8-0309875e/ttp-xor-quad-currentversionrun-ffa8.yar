rule TTP_XOR_QUAD_CurrentVersionRun_ffa8 {
  strings:
    $key_ffa8 = { ac c7 [2] 88 c9 [2] a3 e5 [2] 8d c7 [2] 99 dc [2] 96 c6 [2] 88 db [2] 8a da [2] 91 dc [2] 8d db [2] 91 f4 }

  condition:
    any of them
}