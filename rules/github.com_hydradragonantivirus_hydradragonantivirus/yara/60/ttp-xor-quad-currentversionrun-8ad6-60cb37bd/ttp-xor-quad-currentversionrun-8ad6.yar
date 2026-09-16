rule TTP_XOR_QUAD_CurrentVersionRun_8ad6 {
  strings:
    $key_8ad6 = { d9 b9 [2] fd b7 [2] d6 9b [2] f8 b9 [2] ec a2 [2] e3 b8 [2] fd a5 [2] ff a4 [2] e4 a2 [2] f8 a5 [2] e4 8a }

  condition:
    any of them
}