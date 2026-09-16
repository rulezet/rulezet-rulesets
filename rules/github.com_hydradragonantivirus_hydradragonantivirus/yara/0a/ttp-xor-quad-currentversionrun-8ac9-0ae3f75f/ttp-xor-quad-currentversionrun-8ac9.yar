rule TTP_XOR_QUAD_CurrentVersionRun_8ac9 {
  strings:
    $key_8ac9 = { d9 a6 [2] fd a8 [2] d6 84 [2] f8 a6 [2] ec bd [2] e3 a7 [2] fd ba [2] ff bb [2] e4 bd [2] f8 ba [2] e4 95 }

  condition:
    any of them
}