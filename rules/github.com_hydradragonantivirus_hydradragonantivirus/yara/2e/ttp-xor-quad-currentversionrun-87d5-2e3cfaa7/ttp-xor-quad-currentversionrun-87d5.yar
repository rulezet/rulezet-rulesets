rule TTP_XOR_QUAD_CurrentVersionRun_87d5 {
  strings:
    $key_87d5 = { d4 ba [2] f0 b4 [2] db 98 [2] f5 ba [2] e1 a1 [2] ee bb [2] f0 a6 [2] f2 a7 [2] e9 a1 [2] f5 a6 [2] e9 89 }

  condition:
    any of them
}