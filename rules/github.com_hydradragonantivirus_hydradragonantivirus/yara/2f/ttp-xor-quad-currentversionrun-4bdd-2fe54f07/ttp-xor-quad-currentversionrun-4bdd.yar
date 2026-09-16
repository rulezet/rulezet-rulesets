rule TTP_XOR_QUAD_CurrentVersionRun_4bdd {
  strings:
    $key_4bdd = { 18 b2 [2] 3c bc [2] 17 90 [2] 39 b2 [2] 2d a9 [2] 22 b3 [2] 3c ae [2] 3e af [2] 25 a9 [2] 39 ae [2] 25 81 }

  condition:
    any of them
}