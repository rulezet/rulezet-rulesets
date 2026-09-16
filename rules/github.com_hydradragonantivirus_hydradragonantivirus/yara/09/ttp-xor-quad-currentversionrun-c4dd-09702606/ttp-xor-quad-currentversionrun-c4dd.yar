rule TTP_XOR_QUAD_CurrentVersionRun_c4dd {
  strings:
    $key_c4dd = { 97 b2 [2] b3 bc [2] 98 90 [2] b6 b2 [2] a2 a9 [2] ad b3 [2] b3 ae [2] b1 af [2] aa a9 [2] b6 ae [2] aa 81 }

  condition:
    any of them
}