rule TTP_XOR_QUAD_CurrentVersionRun_ede6 {
  strings:
    $key_ede6 = { be 89 [2] 9a 87 [2] b1 ab [2] 9f 89 [2] 8b 92 [2] 84 88 [2] 9a 95 [2] 98 94 [2] 83 92 [2] 9f 95 [2] 83 ba }

  condition:
    any of them
}