rule TTP_XOR_QUAD_CurrentVersionRun_0fc2 {
  strings:
    $key_0fc2 = { 5c ad [2] 78 a3 [2] 53 8f [2] 7d ad [2] 69 b6 [2] 66 ac [2] 78 b1 [2] 7a b0 [2] 61 b6 [2] 7d b1 [2] 61 9e }

  condition:
    any of them
}