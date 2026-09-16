rule TTP_XOR_QUAD_CurrentVersionRun_8d95 {
  strings:
    $key_8d95 = { de fa [2] fa f4 [2] d1 d8 [2] ff fa [2] eb e1 [2] e4 fb [2] fa e6 [2] f8 e7 [2] e3 e1 [2] ff e6 [2] e3 c9 }

  condition:
    any of them
}