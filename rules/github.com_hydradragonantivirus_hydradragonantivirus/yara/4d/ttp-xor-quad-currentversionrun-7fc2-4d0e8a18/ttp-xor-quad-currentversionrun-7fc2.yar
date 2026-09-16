rule TTP_XOR_QUAD_CurrentVersionRun_7fc2 {
  strings:
    $key_7fc2 = { 2c ad [2] 08 a3 [2] 23 8f [2] 0d ad [2] 19 b6 [2] 16 ac [2] 08 b1 [2] 0a b0 [2] 11 b6 [2] 0d b1 [2] 11 9e }

  condition:
    any of them
}