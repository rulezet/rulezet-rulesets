rule TTP_XOR_QUAD_CurrentVersionRun_fbc2 {
  strings:
    $key_fbc2 = { a8 ad [2] 8c a3 [2] a7 8f [2] 89 ad [2] 9d b6 [2] 92 ac [2] 8c b1 [2] 8e b0 [2] 95 b6 [2] 89 b1 [2] 95 9e }

  condition:
    any of them
}