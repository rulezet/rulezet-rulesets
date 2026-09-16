rule TTP_XOR_QUAD_CurrentVersionRun_ec12 {
  strings:
    $key_ec12 = { bf 7d [2] 9b 73 [2] b0 5f [2] 9e 7d [2] 8a 66 [2] 85 7c [2] 9b 61 [2] 99 60 [2] 82 66 [2] 9e 61 [2] 82 4e }

  condition:
    any of them
}