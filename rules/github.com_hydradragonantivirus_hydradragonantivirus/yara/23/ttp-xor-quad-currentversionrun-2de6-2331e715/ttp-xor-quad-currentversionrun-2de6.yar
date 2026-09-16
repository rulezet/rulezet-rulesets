rule TTP_XOR_QUAD_CurrentVersionRun_2de6 {
  strings:
    $key_2de6 = { 7e 89 [2] 5a 87 [2] 71 ab [2] 5f 89 [2] 4b 92 [2] 44 88 [2] 5a 95 [2] 58 94 [2] 43 92 [2] 5f 95 [2] 43 ba }

  condition:
    any of them
}