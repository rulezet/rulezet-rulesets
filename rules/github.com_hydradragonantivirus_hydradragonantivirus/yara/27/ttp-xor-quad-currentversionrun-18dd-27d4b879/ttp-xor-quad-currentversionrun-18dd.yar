rule TTP_XOR_QUAD_CurrentVersionRun_18dd {
  strings:
    $key_18dd = { 4b b2 [2] 6f bc [2] 44 90 [2] 6a b2 [2] 7e a9 [2] 71 b3 [2] 6f ae [2] 6d af [2] 76 a9 [2] 6a ae [2] 76 81 }

  condition:
    any of them
}