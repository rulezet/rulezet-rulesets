rule TTP_XOR_QUAD_CurrentVersionRun_8ec2 {
  strings:
    $key_8ec2 = { dd ad [2] f9 a3 [2] d2 8f [2] fc ad [2] e8 b6 [2] e7 ac [2] f9 b1 [2] fb b0 [2] e0 b6 [2] fc b1 [2] e0 9e }

  condition:
    any of them
}