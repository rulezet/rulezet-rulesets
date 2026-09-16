rule TTP_XOR_QUAD_CurrentVersionRun_7cdd {
  strings:
    $key_7cdd = { 2f b2 [2] 0b bc [2] 20 90 [2] 0e b2 [2] 1a a9 [2] 15 b3 [2] 0b ae [2] 09 af [2] 12 a9 [2] 0e ae [2] 12 81 }

  condition:
    any of them
}