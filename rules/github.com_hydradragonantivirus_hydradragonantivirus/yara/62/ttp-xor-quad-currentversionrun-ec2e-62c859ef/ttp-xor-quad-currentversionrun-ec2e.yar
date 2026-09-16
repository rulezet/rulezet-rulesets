rule TTP_XOR_QUAD_CurrentVersionRun_ec2e {
  strings:
    $key_ec2e = { bf 41 [2] 9b 4f [2] b0 63 [2] 9e 41 [2] 8a 5a [2] 85 40 [2] 9b 5d [2] 99 5c [2] 82 5a [2] 9e 5d [2] 82 72 }

  condition:
    any of them
}