rule TTP_XOR_QUAD_CurrentVersionRun_8a97 {
  strings:
    $key_8a97 = { d9 f8 [2] fd f6 [2] d6 da [2] f8 f8 [2] ec e3 [2] e3 f9 [2] fd e4 [2] ff e5 [2] e4 e3 [2] f8 e4 [2] e4 cb }

  condition:
    any of them
}