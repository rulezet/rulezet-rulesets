rule TTP_XOR_QUAD_CurrentVersionRun_4dc0 {
  strings:
    $key_4dc0 = { 1e af [2] 3a a1 [2] 11 8d [2] 3f af [2] 2b b4 [2] 24 ae [2] 3a b3 [2] 38 b2 [2] 23 b4 [2] 3f b3 [2] 23 9c }

  condition:
    any of them
}