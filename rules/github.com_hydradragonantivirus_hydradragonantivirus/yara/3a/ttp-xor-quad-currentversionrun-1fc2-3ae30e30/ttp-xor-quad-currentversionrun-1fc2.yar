rule TTP_XOR_QUAD_CurrentVersionRun_1fc2 {
  strings:
    $key_1fc2 = { 4c ad [2] 68 a3 [2] 43 8f [2] 6d ad [2] 79 b6 [2] 76 ac [2] 68 b1 [2] 6a b0 [2] 71 b6 [2] 6d b1 [2] 71 9e }

  condition:
    any of them
}