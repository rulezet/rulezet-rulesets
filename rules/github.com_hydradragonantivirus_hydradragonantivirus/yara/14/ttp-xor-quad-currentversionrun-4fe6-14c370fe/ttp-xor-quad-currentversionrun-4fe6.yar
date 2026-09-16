rule TTP_XOR_QUAD_CurrentVersionRun_4fe6 {
  strings:
    $key_4fe6 = { 1c 89 [2] 38 87 [2] 13 ab [2] 3d 89 [2] 29 92 [2] 26 88 [2] 38 95 [2] 3a 94 [2] 21 92 [2] 3d 95 [2] 21 ba }

  condition:
    any of them
}