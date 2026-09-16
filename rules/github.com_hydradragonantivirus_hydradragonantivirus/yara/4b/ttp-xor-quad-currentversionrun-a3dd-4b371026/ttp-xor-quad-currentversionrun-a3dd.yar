rule TTP_XOR_QUAD_CurrentVersionRun_a3dd {
  strings:
    $key_a3dd = { f0 b2 [2] d4 bc [2] ff 90 [2] d1 b2 [2] c5 a9 [2] ca b3 [2] d4 ae [2] d6 af [2] cd a9 [2] d1 ae [2] cd 81 }

  condition:
    any of them
}