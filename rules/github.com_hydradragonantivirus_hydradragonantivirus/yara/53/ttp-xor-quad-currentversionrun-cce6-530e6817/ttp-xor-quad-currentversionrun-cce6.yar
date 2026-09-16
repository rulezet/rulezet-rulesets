rule TTP_XOR_QUAD_CurrentVersionRun_cce6 {
  strings:
    $key_cce6 = { 9f 89 [2] bb 87 [2] 90 ab [2] be 89 [2] aa 92 [2] a5 88 [2] bb 95 [2] b9 94 [2] a2 92 [2] be 95 [2] a2 ba }

  condition:
    any of them
}