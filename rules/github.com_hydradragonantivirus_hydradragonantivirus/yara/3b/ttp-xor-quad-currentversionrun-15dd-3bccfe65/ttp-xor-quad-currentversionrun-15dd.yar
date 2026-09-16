rule TTP_XOR_QUAD_CurrentVersionRun_15dd {
  strings:
    $key_15dd = { 46 b2 [2] 62 bc [2] 49 90 [2] 67 b2 [2] 73 a9 [2] 7c b3 [2] 62 ae [2] 60 af [2] 7b a9 [2] 67 ae [2] 7b 81 }

  condition:
    any of them
}