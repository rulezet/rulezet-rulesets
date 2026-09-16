rule TTP_XOR_QUAD_CurrentVersionRun_8a87 {
  strings:
    $key_8a87 = { d9 e8 [2] fd e6 [2] d6 ca [2] f8 e8 [2] ec f3 [2] e3 e9 [2] fd f4 [2] ff f5 [2] e4 f3 [2] f8 f4 [2] e4 db }

  condition:
    any of them
}