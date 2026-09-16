rule TTP_XOR_QUAD_CurrentVersionRun_19e6 {
  strings:
    $key_19e6 = { 4a 89 [2] 6e 87 [2] 45 ab [2] 6b 89 [2] 7f 92 [2] 70 88 [2] 6e 95 [2] 6c 94 [2] 77 92 [2] 6b 95 [2] 77 ba }

  condition:
    any of them
}