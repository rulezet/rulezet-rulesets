rule TTP_XOR_QUAD_CurrentVersionRun_ece6 {
  strings:
    $key_ece6 = { bf 89 [2] 9b 87 [2] b0 ab [2] 9e 89 [2] 8a 92 [2] 85 88 [2] 9b 95 [2] 99 94 [2] 82 92 [2] 9e 95 [2] 82 ba }

  condition:
    any of them
}