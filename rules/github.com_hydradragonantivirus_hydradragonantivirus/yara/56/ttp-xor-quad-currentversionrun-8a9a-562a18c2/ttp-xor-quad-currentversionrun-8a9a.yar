rule TTP_XOR_QUAD_CurrentVersionRun_8a9a {
  strings:
    $key_8a9a = { d9 f5 [2] fd fb [2] d6 d7 [2] f8 f5 [2] ec ee [2] e3 f4 [2] fd e9 [2] ff e8 [2] e4 ee [2] f8 e9 [2] e4 c6 }

  condition:
    any of them
}