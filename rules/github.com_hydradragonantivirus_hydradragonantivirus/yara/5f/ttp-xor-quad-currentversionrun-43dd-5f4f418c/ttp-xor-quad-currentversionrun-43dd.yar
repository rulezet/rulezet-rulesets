rule TTP_XOR_QUAD_CurrentVersionRun_43dd {
  strings:
    $key_43dd = { 10 b2 [2] 34 bc [2] 1f 90 [2] 31 b2 [2] 25 a9 [2] 2a b3 [2] 34 ae [2] 36 af [2] 2d a9 [2] 31 ae [2] 2d 81 }

  condition:
    any of them
}