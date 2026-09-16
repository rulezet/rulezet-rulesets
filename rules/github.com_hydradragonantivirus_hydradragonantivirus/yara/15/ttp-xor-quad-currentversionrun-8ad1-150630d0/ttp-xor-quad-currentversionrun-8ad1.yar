rule TTP_XOR_QUAD_CurrentVersionRun_8ad1 {
  strings:
    $key_8ad1 = { d9 be [2] fd b0 [2] d6 9c [2] f8 be [2] ec a5 [2] e3 bf [2] fd a2 [2] ff a3 [2] e4 a5 [2] f8 a2 [2] e4 8d }

  condition:
    any of them
}