rule TTP_XOR_QUAD_CurrentVersionRun_87d2 {
  strings:
    $key_87d2 = { d4 bd [2] f0 b3 [2] db 9f [2] f5 bd [2] e1 a6 [2] ee bc [2] f0 a1 [2] f2 a0 [2] e9 a6 [2] f5 a1 [2] e9 8e }

  condition:
    any of them
}