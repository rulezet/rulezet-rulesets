rule TTP_XOR_QUAD_CurrentVersionRun_78e6 {
  strings:
    $key_78e6 = { 2b 89 [2] 0f 87 [2] 24 ab [2] 0a 89 [2] 1e 92 [2] 11 88 [2] 0f 95 [2] 0d 94 [2] 16 92 [2] 0a 95 [2] 16 ba }

  condition:
    any of them
}