rule TTP_XOR_QUAD_CurrentVersionRun_e2dd {
  strings:
    $key_e2dd = { b1 b2 [2] 95 bc [2] be 90 [2] 90 b2 [2] 84 a9 [2] 8b b3 [2] 95 ae [2] 97 af [2] 8c a9 [2] 90 ae [2] 8c 81 }

  condition:
    any of them
}