rule TTP_XOR_QUAD_CurrentVersionRun_07dd {
  strings:
    $key_07dd = { 54 b2 [2] 70 bc [2] 5b 90 [2] 75 b2 [2] 61 a9 [2] 6e b3 [2] 70 ae [2] 72 af [2] 69 a9 [2] 75 ae [2] 69 81 }

  condition:
    any of them
}