rule TTP_XOR_QUAD_CurrentVersionRun_d0dd {
  strings:
    $key_d0dd = { 83 b2 [2] a7 bc [2] 8c 90 [2] a2 b2 [2] b6 a9 [2] b9 b3 [2] a7 ae [2] a5 af [2] be a9 [2] a2 ae [2] be 81 }

  condition:
    any of them
}