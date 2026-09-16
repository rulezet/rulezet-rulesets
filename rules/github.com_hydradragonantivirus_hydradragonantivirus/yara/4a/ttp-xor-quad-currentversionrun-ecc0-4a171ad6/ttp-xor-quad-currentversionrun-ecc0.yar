rule TTP_XOR_QUAD_CurrentVersionRun_ecc0 {
  strings:
    $key_ecc0 = { bf af [2] 9b a1 [2] b0 8d [2] 9e af [2] 8a b4 [2] 85 ae [2] 9b b3 [2] 99 b2 [2] 82 b4 [2] 9e b3 [2] 82 9c }

  condition:
    any of them
}