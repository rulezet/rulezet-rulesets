rule TTP_XOR_QUAD_CurrentVersionRun_8a94 {
  strings:
    $key_8a94 = { d9 fb [2] fd f5 [2] d6 d9 [2] f8 fb [2] ec e0 [2] e3 fa [2] fd e7 [2] ff e6 [2] e4 e0 [2] f8 e7 [2] e4 c8 }

  condition:
    any of them
}