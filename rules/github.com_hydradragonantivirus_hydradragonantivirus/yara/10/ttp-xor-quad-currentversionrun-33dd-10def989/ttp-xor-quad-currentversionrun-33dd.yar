rule TTP_XOR_QUAD_CurrentVersionRun_33dd {
  strings:
    $key_33dd = { 60 b2 [2] 44 bc [2] 6f 90 [2] 41 b2 [2] 55 a9 [2] 5a b3 [2] 44 ae [2] 46 af [2] 5d a9 [2] 41 ae [2] 5d 81 }

  condition:
    any of them
}