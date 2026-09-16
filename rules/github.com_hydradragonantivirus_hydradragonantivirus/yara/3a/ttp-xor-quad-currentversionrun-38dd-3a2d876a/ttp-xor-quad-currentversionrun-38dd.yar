rule TTP_XOR_QUAD_CurrentVersionRun_38dd {
  strings:
    $key_38dd = { 6b b2 [2] 4f bc [2] 64 90 [2] 4a b2 [2] 5e a9 [2] 51 b3 [2] 4f ae [2] 4d af [2] 56 a9 [2] 4a ae [2] 56 81 }

  condition:
    any of them
}