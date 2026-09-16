rule TTP_XOR_QUAD_CurrentVersionRun_5ec1 {
  strings:
    $key_5ec1 = { 0d ae [2] 29 a0 [2] 02 8c [2] 2c ae [2] 38 b5 [2] 37 af [2] 29 b2 [2] 2b b3 [2] 30 b5 [2] 2c b2 [2] 30 9d }

  condition:
    any of them
}