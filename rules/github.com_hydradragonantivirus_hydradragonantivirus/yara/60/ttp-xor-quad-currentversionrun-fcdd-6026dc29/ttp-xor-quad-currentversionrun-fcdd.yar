rule TTP_XOR_QUAD_CurrentVersionRun_fcdd {
  strings:
    $key_fcdd = { af b2 [2] 8b bc [2] a0 90 [2] 8e b2 [2] 9a a9 [2] 95 b3 [2] 8b ae [2] 89 af [2] 92 a9 [2] 8e ae [2] 92 81 }

  condition:
    any of them
}