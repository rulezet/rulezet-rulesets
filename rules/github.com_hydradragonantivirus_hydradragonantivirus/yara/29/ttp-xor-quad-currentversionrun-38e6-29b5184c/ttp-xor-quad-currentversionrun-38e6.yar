rule TTP_XOR_QUAD_CurrentVersionRun_38e6 {
  strings:
    $key_38e6 = { 6b 89 [2] 4f 87 [2] 64 ab [2] 4a 89 [2] 5e 92 [2] 51 88 [2] 4f 95 [2] 4d 94 [2] 56 92 [2] 4a 95 [2] 56 ba }

  condition:
    any of them
}