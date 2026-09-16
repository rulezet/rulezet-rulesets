rule TTP_XOR_QUAD_CurrentVersionRun_0ec2 {
  strings:
    $key_0ec2 = { 5d ad [2] 79 a3 [2] 52 8f [2] 7c ad [2] 68 b6 [2] 67 ac [2] 79 b1 [2] 7b b0 [2] 60 b6 [2] 7c b1 [2] 60 9e }

  condition:
    any of them
}