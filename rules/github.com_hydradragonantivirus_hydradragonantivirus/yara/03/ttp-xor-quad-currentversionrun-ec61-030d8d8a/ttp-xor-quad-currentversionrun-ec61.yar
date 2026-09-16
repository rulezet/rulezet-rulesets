rule TTP_XOR_QUAD_CurrentVersionRun_ec61 {
  strings:
    $key_ec61 = { bf 0e [2] 9b 00 [2] b0 2c [2] 9e 0e [2] 8a 15 [2] 85 0f [2] 9b 12 [2] 99 13 [2] 82 15 [2] 9e 12 [2] 82 3d }

  condition:
    any of them
}