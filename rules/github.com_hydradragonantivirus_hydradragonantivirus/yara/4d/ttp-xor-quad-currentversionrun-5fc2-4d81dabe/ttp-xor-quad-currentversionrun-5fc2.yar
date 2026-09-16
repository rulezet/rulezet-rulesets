rule TTP_XOR_QUAD_CurrentVersionRun_5fc2 {
  strings:
    $key_5fc2 = { 0c ad [2] 28 a3 [2] 03 8f [2] 2d ad [2] 39 b6 [2] 36 ac [2] 28 b1 [2] 2a b0 [2] 31 b6 [2] 2d b1 [2] 31 9e }

  condition:
    any of them
}