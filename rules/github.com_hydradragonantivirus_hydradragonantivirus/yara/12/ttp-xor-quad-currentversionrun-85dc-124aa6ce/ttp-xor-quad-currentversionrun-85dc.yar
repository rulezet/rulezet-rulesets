rule TTP_XOR_QUAD_CurrentVersionRun_85dc {
  strings:
    $key_85dc = { d6 b3 [2] f2 bd [2] d9 91 [2] f7 b3 [2] e3 a8 [2] ec b2 [2] f2 af [2] f0 ae [2] eb a8 [2] f7 af [2] eb 80 }

  condition:
    any of them
}