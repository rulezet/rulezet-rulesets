rule TTP_XOR_QUAD_CurrentVersionRun_c3dd {
  strings:
    $key_c3dd = { 90 b2 [2] b4 bc [2] 9f 90 [2] b1 b2 [2] a5 a9 [2] aa b3 [2] b4 ae [2] b6 af [2] ad a9 [2] b1 ae [2] ad 81 }

  condition:
    any of them
}