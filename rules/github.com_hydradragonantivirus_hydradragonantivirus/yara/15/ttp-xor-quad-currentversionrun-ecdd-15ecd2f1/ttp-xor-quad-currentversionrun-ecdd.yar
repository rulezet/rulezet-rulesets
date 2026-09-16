rule TTP_XOR_QUAD_CurrentVersionRun_ecdd {
  strings:
    $key_ecdd = { bf b2 [2] 9b bc [2] b0 90 [2] 9e b2 [2] 8a a9 [2] 85 b3 [2] 9b ae [2] 99 af [2] 82 a9 [2] 9e ae [2] 82 81 }

  condition:
    any of them
}