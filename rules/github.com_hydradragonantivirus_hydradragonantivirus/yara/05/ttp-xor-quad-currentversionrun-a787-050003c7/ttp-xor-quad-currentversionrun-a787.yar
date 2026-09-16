rule TTP_XOR_QUAD_CurrentVersionRun_a787 {
  strings:
    $key_a787 = { f4 e8 [2] d0 e6 [2] fb ca [2] d5 e8 [2] c1 f3 [2] ce e9 [2] d0 f4 [2] d2 f5 [2] c9 f3 [2] d5 f4 [2] c9 db }

  condition:
    any of them
}