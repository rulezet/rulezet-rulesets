rule TTP_XOR_QUAD_CurrentVersionRun_5ac2 {
  strings:
    $key_5ac2 = { 09 ad [2] 2d a3 [2] 06 8f [2] 28 ad [2] 3c b6 [2] 33 ac [2] 2d b1 [2] 2f b0 [2] 34 b6 [2] 28 b1 [2] 34 9e }

  condition:
    any of them
}