rule TTP_XOR_QUAD_CurrentVersionRun_5dc0 {
  strings:
    $key_5dc0 = { 0e af [2] 2a a1 [2] 01 8d [2] 2f af [2] 3b b4 [2] 34 ae [2] 2a b3 [2] 28 b2 [2] 33 b4 [2] 2f b3 [2] 33 9c }

  condition:
    any of them
}