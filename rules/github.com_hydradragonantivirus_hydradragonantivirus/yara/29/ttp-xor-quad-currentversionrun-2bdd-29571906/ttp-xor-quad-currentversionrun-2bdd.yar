rule TTP_XOR_QUAD_CurrentVersionRun_2bdd {
  strings:
    $key_2bdd = { 78 b2 [2] 5c bc [2] 77 90 [2] 59 b2 [2] 4d a9 [2] 42 b3 [2] 5c ae [2] 5e af [2] 45 a9 [2] 59 ae [2] 45 81 }

  condition:
    any of them
}