rule TTP_XOR_QUAD_CurrentVersionRun_78dd {
  strings:
    $key_78dd = { 2b b2 [2] 0f bc [2] 24 90 [2] 0a b2 [2] 1e a9 [2] 11 b3 [2] 0f ae [2] 0d af [2] 16 a9 [2] 0a ae [2] 16 81 }

  condition:
    any of them
}