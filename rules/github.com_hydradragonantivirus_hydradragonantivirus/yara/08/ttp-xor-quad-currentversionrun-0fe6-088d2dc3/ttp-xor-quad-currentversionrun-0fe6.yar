rule TTP_XOR_QUAD_CurrentVersionRun_0fe6 {
  strings:
    $key_0fe6 = { 5c 89 [2] 78 87 [2] 53 ab [2] 7d 89 [2] 69 92 [2] 66 88 [2] 78 95 [2] 7a 94 [2] 61 92 [2] 7d 95 [2] 61 ba }

  condition:
    any of them
}