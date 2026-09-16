rule TTP_XOR_QUAD_CurrentVersionRun_4ee6 {
  strings:
    $key_4ee6 = { 1d 89 [2] 39 87 [2] 12 ab [2] 3c 89 [2] 28 92 [2] 27 88 [2] 39 95 [2] 3b 94 [2] 20 92 [2] 3c 95 [2] 20 ba }

  condition:
    any of them
}