rule TTP_XOR_QUAD_CurrentVersionRun_5ec2 {
  strings:
    $key_5ec2 = { 0d ad [2] 29 a3 [2] 02 8f [2] 2c ad [2] 38 b6 [2] 37 ac [2] 29 b1 [2] 2b b0 [2] 30 b6 [2] 2c b1 [2] 30 9e }

  condition:
    any of them
}