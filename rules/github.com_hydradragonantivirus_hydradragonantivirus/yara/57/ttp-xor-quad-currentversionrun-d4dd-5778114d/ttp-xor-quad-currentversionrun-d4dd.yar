rule TTP_XOR_QUAD_CurrentVersionRun_d4dd {
  strings:
    $key_d4dd = { 87 b2 [2] a3 bc [2] 88 90 [2] a6 b2 [2] b2 a9 [2] bd b3 [2] a3 ae [2] a1 af [2] ba a9 [2] a6 ae [2] ba 81 }

  condition:
    any of them
}