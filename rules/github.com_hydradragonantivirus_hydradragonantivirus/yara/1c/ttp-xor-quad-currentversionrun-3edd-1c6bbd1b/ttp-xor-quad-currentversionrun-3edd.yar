rule TTP_XOR_QUAD_CurrentVersionRun_3edd {
  strings:
    $key_3edd = { 6d b2 [2] 49 bc [2] 62 90 [2] 4c b2 [2] 58 a9 [2] 57 b3 [2] 49 ae [2] 4b af [2] 50 a9 [2] 4c ae [2] 50 81 }

  condition:
    any of them
}