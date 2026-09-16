rule TTP_XOR_QUAD_CurrentVersionRun_8ac1 {
  strings:
    $key_8ac1 = { d9 ae [2] fd a0 [2] d6 8c [2] f8 ae [2] ec b5 [2] e3 af [2] fd b2 [2] ff b3 [2] e4 b5 [2] f8 b2 [2] e4 9d }

  condition:
    any of them
}