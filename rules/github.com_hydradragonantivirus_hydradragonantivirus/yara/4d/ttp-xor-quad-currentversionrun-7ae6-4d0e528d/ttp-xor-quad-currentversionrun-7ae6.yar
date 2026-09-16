rule TTP_XOR_QUAD_CurrentVersionRun_7ae6 {
  strings:
    $key_7ae6 = { 29 89 [2] 0d 87 [2] 26 ab [2] 08 89 [2] 1c 92 [2] 13 88 [2] 0d 95 [2] 0f 94 [2] 14 92 [2] 08 95 [2] 14 ba }

  condition:
    any of them
}