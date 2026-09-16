rule TTP_XOR_QUAD_CurrentVersionRun_8aca {
  strings:
    $key_8aca = { d9 a5 [2] fd ab [2] d6 87 [2] f8 a5 [2] ec be [2] e3 a4 [2] fd b9 [2] ff b8 [2] e4 be [2] f8 b9 [2] e4 96 }

  condition:
    any of them
}