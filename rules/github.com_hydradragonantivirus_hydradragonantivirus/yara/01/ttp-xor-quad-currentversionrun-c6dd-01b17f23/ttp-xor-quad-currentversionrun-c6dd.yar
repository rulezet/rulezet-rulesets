rule TTP_XOR_QUAD_CurrentVersionRun_c6dd {
  strings:
    $key_c6dd = { 95 b2 [2] b1 bc [2] 9a 90 [2] b4 b2 [2] a0 a9 [2] af b3 [2] b1 ae [2] b3 af [2] a8 a9 [2] b4 ae [2] a8 81 }

  condition:
    any of them
}