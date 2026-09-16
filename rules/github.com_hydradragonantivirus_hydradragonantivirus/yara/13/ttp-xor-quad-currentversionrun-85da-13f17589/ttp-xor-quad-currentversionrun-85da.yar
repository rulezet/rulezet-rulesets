rule TTP_XOR_QUAD_CurrentVersionRun_85da {
  strings:
    $key_85da = { d6 b5 [2] f2 bb [2] d9 97 [2] f7 b5 [2] e3 ae [2] ec b4 [2] f2 a9 [2] f0 a8 [2] eb ae [2] f7 a9 [2] eb 86 }

  condition:
    any of them
}