rule TTP_XOR_QUAD_CurrentVersionRun_25dd {
  strings:
    $key_25dd = { 76 b2 [2] 52 bc [2] 79 90 [2] 57 b2 [2] 43 a9 [2] 4c b3 [2] 52 ae [2] 50 af [2] 4b a9 [2] 57 ae [2] 4b 81 }

  condition:
    any of them
}