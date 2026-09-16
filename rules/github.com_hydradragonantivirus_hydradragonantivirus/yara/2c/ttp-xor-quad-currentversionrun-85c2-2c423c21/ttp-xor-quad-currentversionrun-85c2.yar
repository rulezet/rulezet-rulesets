rule TTP_XOR_QUAD_CurrentVersionRun_85c2 {
  strings:
    $key_85c2 = { d6 ad [2] f2 a3 [2] d9 8f [2] f7 ad [2] e3 b6 [2] ec ac [2] f2 b1 [2] f0 b0 [2] eb b6 [2] f7 b1 [2] eb 9e }

  condition:
    any of them
}