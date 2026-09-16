rule TTP_XOR_QUAD_CurrentVersionRun_28dd {
  strings:
    $key_28dd = { 7b b2 [2] 5f bc [2] 74 90 [2] 5a b2 [2] 4e a9 [2] 41 b3 [2] 5f ae [2] 5d af [2] 46 a9 [2] 5a ae [2] 46 81 }

  condition:
    any of them
}