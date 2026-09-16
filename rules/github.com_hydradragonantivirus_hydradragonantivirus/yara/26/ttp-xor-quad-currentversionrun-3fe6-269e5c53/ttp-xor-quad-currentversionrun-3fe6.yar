rule TTP_XOR_QUAD_CurrentVersionRun_3fe6 {
  strings:
    $key_3fe6 = { 6c 89 [2] 48 87 [2] 63 ab [2] 4d 89 [2] 59 92 [2] 56 88 [2] 48 95 [2] 4a 94 [2] 51 92 [2] 4d 95 [2] 51 ba }

  condition:
    any of them
}