rule TTP_XOR_QUAD_CurrentVersionRun_d4dc {
  strings:
    $key_d4dc = { 87 b3 [2] a3 bd [2] 88 91 [2] a6 b3 [2] b2 a8 [2] bd b2 [2] a3 af [2] a1 ae [2] ba a8 [2] a6 af [2] ba 80 }

  condition:
    any of them
}