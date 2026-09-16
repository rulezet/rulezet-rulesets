rule TTP_XOR_QUAD_CurrentVersionRun_4cdd {
  strings:
    $key_4cdd = { 1f b2 [2] 3b bc [2] 10 90 [2] 3e b2 [2] 2a a9 [2] 25 b3 [2] 3b ae [2] 39 af [2] 22 a9 [2] 3e ae [2] 22 81 }

  condition:
    any of them
}