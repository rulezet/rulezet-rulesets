rule TTP_XOR_QUAD_CurrentVersionRun_1bdd {
  strings:
    $key_1bdd = { 48 b2 [2] 6c bc [2] 47 90 [2] 69 b2 [2] 7d a9 [2] 72 b3 [2] 6c ae [2] 6e af [2] 75 a9 [2] 69 ae [2] 75 81 }

  condition:
    any of them
}