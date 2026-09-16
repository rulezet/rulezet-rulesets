rule TTP_XOR_QUAD_CurrentVersionRun_0de6 {
  strings:
    $key_0de6 = { 5e 89 [2] 7a 87 [2] 51 ab [2] 7f 89 [2] 6b 92 [2] 64 88 [2] 7a 95 [2] 78 94 [2] 63 92 [2] 7f 95 [2] 63 ba }

  condition:
    any of them
}