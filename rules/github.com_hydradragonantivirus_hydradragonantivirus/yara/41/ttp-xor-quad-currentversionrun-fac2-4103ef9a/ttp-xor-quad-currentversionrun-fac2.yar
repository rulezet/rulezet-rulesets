rule TTP_XOR_QUAD_CurrentVersionRun_fac2 {
  strings:
    $key_fac2 = { a9 ad [2] 8d a3 [2] a6 8f [2] 88 ad [2] 9c b6 [2] 93 ac [2] 8d b1 [2] 8f b0 [2] 94 b6 [2] 88 b1 [2] 94 9e }

  condition:
    any of them
}