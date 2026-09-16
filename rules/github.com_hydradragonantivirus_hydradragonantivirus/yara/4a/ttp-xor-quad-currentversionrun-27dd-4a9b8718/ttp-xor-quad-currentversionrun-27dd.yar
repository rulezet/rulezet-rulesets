rule TTP_XOR_QUAD_CurrentVersionRun_27dd {
  strings:
    $key_27dd = { 74 b2 [2] 50 bc [2] 7b 90 [2] 55 b2 [2] 41 a9 [2] 4e b3 [2] 50 ae [2] 52 af [2] 49 a9 [2] 55 ae [2] 49 81 }

  condition:
    any of them
}