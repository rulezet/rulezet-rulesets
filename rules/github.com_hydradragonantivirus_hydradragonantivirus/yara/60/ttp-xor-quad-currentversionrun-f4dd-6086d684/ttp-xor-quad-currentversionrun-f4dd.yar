rule TTP_XOR_QUAD_CurrentVersionRun_f4dd {
  strings:
    $key_f4dd = { a7 b2 [2] 83 bc [2] a8 90 [2] 86 b2 [2] 92 a9 [2] 9d b3 [2] 83 ae [2] 81 af [2] 9a a9 [2] 86 ae [2] 9a 81 }

  condition:
    any of them
}