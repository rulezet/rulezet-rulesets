rule TTP_XOR_QUAD_CurrentVersionRun_5ec0 {
  strings:
    $key_5ec0 = { 0d af [2] 29 a1 [2] 02 8d [2] 2c af [2] 38 b4 [2] 37 ae [2] 29 b3 [2] 2b b2 [2] 30 b4 [2] 2c b3 [2] 30 9c }

  condition:
    any of them
}