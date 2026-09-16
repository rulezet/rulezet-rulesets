rule TTP_XOR_QUAD_CurrentVersionRun_fee6 {
  strings:
    $key_fee6 = { ad 89 [2] 89 87 [2] a2 ab [2] 8c 89 [2] 98 92 [2] 97 88 [2] 89 95 [2] 8b 94 [2] 90 92 [2] 8c 95 [2] 90 ba }

  condition:
    any of them
}