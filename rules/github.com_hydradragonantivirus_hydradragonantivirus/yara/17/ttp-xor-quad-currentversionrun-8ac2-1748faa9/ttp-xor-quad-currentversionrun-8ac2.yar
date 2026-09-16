rule TTP_XOR_QUAD_CurrentVersionRun_8ac2 {
  strings:
    $key_8ac2 = { d9 ad [2] fd a3 [2] d6 8f [2] f8 ad [2] ec b6 [2] e3 ac [2] fd b1 [2] ff b0 [2] e4 b6 [2] f8 b1 [2] e4 9e }

  condition:
    any of them
}