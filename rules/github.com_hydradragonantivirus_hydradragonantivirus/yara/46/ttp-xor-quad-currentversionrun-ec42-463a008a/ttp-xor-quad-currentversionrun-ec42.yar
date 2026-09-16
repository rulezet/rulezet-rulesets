rule TTP_XOR_QUAD_CurrentVersionRun_ec42 {
  strings:
    $key_ec42 = { bf 2d [2] 9b 23 [2] b0 0f [2] 9e 2d [2] 8a 36 [2] 85 2c [2] 9b 31 [2] 99 30 [2] 82 36 [2] 9e 31 [2] 82 1e }

  condition:
    any of them
}