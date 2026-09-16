rule TTP_XOR_QUAD_CurrentVersionRun_75dd {
  strings:
    $key_75dd = { 26 b2 [2] 02 bc [2] 29 90 [2] 07 b2 [2] 13 a9 [2] 1c b3 [2] 02 ae [2] 00 af [2] 1b a9 [2] 07 ae [2] 1b 81 }

  condition:
    any of them
}