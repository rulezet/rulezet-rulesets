rule TTP_XOR_QUAD_CurrentVersionRun_8ad7 {
  strings:
    $key_8ad7 = { d9 b8 [2] fd b6 [2] d6 9a [2] f8 b8 [2] ec a3 [2] e3 b9 [2] fd a4 [2] ff a5 [2] e4 a3 [2] f8 a4 [2] e4 8b }

  condition:
    any of them
}