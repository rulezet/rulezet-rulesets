rule TTP_XOR_QUAD_CurrentVersionRun_f2dd {
  strings:
    $key_f2dd = { a1 b2 [2] 85 bc [2] ae 90 [2] 80 b2 [2] 94 a9 [2] 9b b3 [2] 85 ae [2] 87 af [2] 9c a9 [2] 80 ae [2] 9c 81 }

  condition:
    any of them
}