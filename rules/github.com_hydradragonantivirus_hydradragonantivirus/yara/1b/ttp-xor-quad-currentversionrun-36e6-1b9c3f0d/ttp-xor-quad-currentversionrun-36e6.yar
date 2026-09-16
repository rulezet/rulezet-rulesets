rule TTP_XOR_QUAD_CurrentVersionRun_36e6 {
  strings:
    $key_36e6 = { 65 89 [2] 41 87 [2] 6a ab [2] 44 89 [2] 50 92 [2] 5f 88 [2] 41 95 [2] 43 94 [2] 58 92 [2] 44 95 [2] 58 ba }

  condition:
    any of them
}