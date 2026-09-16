rule TTP_XOR_QUAD_CurrentVersionRun_09e6 {
  strings:
    $key_09e6 = { 5a 89 [2] 7e 87 [2] 55 ab [2] 7b 89 [2] 6f 92 [2] 60 88 [2] 7e 95 [2] 7c 94 [2] 67 92 [2] 7b 95 [2] 67 ba }

  condition:
    any of them
}