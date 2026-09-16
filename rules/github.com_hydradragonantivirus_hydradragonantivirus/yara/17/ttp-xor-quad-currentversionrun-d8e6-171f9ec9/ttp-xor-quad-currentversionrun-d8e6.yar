rule TTP_XOR_QUAD_CurrentVersionRun_d8e6 {
  strings:
    $key_d8e6 = { 8b 89 [2] af 87 [2] 84 ab [2] aa 89 [2] be 92 [2] b1 88 [2] af 95 [2] ad 94 [2] b6 92 [2] aa 95 [2] b6 ba }

  condition:
    any of them
}