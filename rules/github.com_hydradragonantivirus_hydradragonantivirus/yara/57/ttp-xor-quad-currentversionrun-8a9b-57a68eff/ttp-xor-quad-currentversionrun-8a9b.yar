rule TTP_XOR_QUAD_CurrentVersionRun_8a9b {
  strings:
    $key_8a9b = { d9 f4 [2] fd fa [2] d6 d6 [2] f8 f4 [2] ec ef [2] e3 f5 [2] fd e8 [2] ff e9 [2] e4 ef [2] f8 e8 [2] e4 c7 }

  condition:
    any of them
}