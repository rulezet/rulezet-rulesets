rule TTP_XOR_QUAD_CurrentVersionRun_4ec2 {
  strings:
    $key_4ec2 = { 1d ad [2] 39 a3 [2] 12 8f [2] 3c ad [2] 28 b6 [2] 27 ac [2] 39 b1 [2] 3b b0 [2] 20 b6 [2] 3c b1 [2] 20 9e }

  condition:
    any of them
}