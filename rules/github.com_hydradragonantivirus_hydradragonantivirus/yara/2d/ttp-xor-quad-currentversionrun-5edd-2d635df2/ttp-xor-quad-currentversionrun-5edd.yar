rule TTP_XOR_QUAD_CurrentVersionRun_5edd {
  strings:
    $key_5edd = { 0d b2 [2] 29 bc [2] 02 90 [2] 2c b2 [2] 38 a9 [2] 37 b3 [2] 29 ae [2] 2b af [2] 30 a9 [2] 2c ae [2] 30 81 }

  condition:
    any of them
}