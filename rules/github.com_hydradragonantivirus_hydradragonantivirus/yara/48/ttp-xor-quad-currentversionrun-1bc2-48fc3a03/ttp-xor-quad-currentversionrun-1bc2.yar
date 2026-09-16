rule TTP_XOR_QUAD_CurrentVersionRun_1bc2 {
  strings:
    $key_1bc2 = { 48 ad [2] 6c a3 [2] 47 8f [2] 69 ad [2] 7d b6 [2] 72 ac [2] 6c b1 [2] 6e b0 [2] 75 b6 [2] 69 b1 [2] 75 9e }

  condition:
    any of them
}