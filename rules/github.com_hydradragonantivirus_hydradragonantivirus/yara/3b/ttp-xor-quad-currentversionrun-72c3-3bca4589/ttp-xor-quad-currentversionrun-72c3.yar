rule TTP_XOR_QUAD_CurrentVersionRun_72c3 {
  strings:
    $key_72c3 = { 21 ac [2] 05 a2 [2] 2e 8e [2] 00 ac [2] 14 b7 [2] 1b ad [2] 05 b0 [2] 07 b1 [2] 1c b7 [2] 00 b0 [2] 1c 9f }

  condition:
    any of them
}