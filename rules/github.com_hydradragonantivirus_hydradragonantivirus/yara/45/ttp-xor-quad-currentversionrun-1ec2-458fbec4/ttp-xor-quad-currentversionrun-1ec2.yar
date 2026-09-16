rule TTP_XOR_QUAD_CurrentVersionRun_1ec2 {
  strings:
    $key_1ec2 = { 4d ad [2] 69 a3 [2] 42 8f [2] 6c ad [2] 78 b6 [2] 77 ac [2] 69 b1 [2] 6b b0 [2] 70 b6 [2] 6c b1 [2] 70 9e }

  condition:
    any of them
}