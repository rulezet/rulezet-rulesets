rule TTP_XOR_QUAD_CurrentVersionRun_8387 {
  strings:
    $key_8387 = { d0 e8 [2] f4 e6 [2] df ca [2] f1 e8 [2] e5 f3 [2] ea e9 [2] f4 f4 [2] f6 f5 [2] ed f3 [2] f1 f4 [2] ed db }

  condition:
    any of them
}