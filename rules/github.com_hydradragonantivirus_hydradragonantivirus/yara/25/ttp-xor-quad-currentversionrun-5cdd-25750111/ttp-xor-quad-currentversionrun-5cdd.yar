rule TTP_XOR_QUAD_CurrentVersionRun_5cdd {
  strings:
    $key_5cdd = { 0f b2 [2] 2b bc [2] 00 90 [2] 2e b2 [2] 3a a9 [2] 35 b3 [2] 2b ae [2] 29 af [2] 32 a9 [2] 2e ae [2] 32 81 }

  condition:
    any of them
}