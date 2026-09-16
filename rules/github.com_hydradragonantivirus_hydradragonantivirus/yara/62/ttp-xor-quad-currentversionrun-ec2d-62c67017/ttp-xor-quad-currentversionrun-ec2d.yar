rule TTP_XOR_QUAD_CurrentVersionRun_ec2d {
  strings:
    $key_ec2d = { bf 42 [2] 9b 4c [2] b0 60 [2] 9e 42 [2] 8a 59 [2] 85 43 [2] 9b 5e [2] 99 5f [2] 82 59 [2] 9e 5e [2] 82 71 }

  condition:
    any of them
}