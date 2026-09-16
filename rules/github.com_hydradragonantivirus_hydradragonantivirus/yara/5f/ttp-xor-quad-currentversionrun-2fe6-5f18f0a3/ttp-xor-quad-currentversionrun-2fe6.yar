rule TTP_XOR_QUAD_CurrentVersionRun_2fe6 {
  strings:
    $key_2fe6 = { 7c 89 [2] 58 87 [2] 73 ab [2] 5d 89 [2] 49 92 [2] 46 88 [2] 58 95 [2] 5a 94 [2] 41 92 [2] 5d 95 [2] 41 ba }

  condition:
    any of them
}