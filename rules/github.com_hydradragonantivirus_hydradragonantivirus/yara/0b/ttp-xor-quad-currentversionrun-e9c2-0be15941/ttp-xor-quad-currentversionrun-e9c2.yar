rule TTP_XOR_QUAD_CurrentVersionRun_e9c2 {
  strings:
    $key_e9c2 = { ba ad [2] 9e a3 [2] b5 8f [2] 9b ad [2] 8f b6 [2] 80 ac [2] 9e b1 [2] 9c b0 [2] 87 b6 [2] 9b b1 [2] 87 9e }

  condition:
    any of them
}