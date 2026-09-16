rule TTP_XOR_QUAD_CurrentVersionRun_8d94 {
  strings:
    $key_8d94 = { de fb [2] fa f5 [2] d1 d9 [2] ff fb [2] eb e0 [2] e4 fa [2] fa e7 [2] f8 e6 [2] e3 e0 [2] ff e7 [2] e3 c8 }

  condition:
    any of them
}