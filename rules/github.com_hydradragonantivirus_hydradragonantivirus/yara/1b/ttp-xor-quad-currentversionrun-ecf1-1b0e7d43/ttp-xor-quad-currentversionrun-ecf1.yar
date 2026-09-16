rule TTP_XOR_QUAD_CurrentVersionRun_ecf1 {
  strings:
    $key_ecf1 = { bf 9e [2] 9b 90 [2] b0 bc [2] 9e 9e [2] 8a 85 [2] 85 9f [2] 9b 82 [2] 99 83 [2] 82 85 [2] 9e 82 [2] 82 ad }

  condition:
    any of them
}