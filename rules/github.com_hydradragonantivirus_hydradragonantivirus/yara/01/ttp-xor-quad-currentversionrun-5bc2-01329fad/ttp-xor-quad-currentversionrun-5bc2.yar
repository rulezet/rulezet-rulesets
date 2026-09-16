rule TTP_XOR_QUAD_CurrentVersionRun_5bc2 {
  strings:
    $key_5bc2 = { 08 ad [2] 2c a3 [2] 07 8f [2] 29 ad [2] 3d b6 [2] 32 ac [2] 2c b1 [2] 2e b0 [2] 35 b6 [2] 29 b1 [2] 35 9e }

  condition:
    any of them
}