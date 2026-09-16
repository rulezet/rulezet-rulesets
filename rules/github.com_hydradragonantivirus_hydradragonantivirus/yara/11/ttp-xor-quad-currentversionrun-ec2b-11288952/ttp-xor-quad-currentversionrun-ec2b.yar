rule TTP_XOR_QUAD_CurrentVersionRun_ec2b {
  strings:
    $key_ec2b = { bf 44 [2] 9b 4a [2] b0 66 [2] 9e 44 [2] 8a 5f [2] 85 45 [2] 9b 58 [2] 99 59 [2] 82 5f [2] 9e 58 [2] 82 77 }

  condition:
    any of them
}