rule TTP_XOR_QUAD_CurrentVersionRun_87d1 {
  strings:
    $key_87d1 = { d4 be [2] f0 b0 [2] db 9c [2] f5 be [2] e1 a5 [2] ee bf [2] f0 a2 [2] f2 a3 [2] e9 a5 [2] f5 a2 [2] e9 8d }

  condition:
    any of them
}