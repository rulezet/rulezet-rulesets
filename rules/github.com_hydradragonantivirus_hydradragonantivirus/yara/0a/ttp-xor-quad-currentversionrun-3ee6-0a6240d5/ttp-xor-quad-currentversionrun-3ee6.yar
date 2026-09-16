rule TTP_XOR_QUAD_CurrentVersionRun_3ee6 {
  strings:
    $key_3ee6 = { 6d 89 [2] 49 87 [2] 62 ab [2] 4c 89 [2] 58 92 [2] 57 88 [2] 49 95 [2] 4b 94 [2] 50 92 [2] 4c 95 [2] 50 ba }

  condition:
    any of them
}