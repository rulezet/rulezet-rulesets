rule TTP_XOR_QUAD_CurrentVersionRun_f9e6 {
  strings:
    $key_f9e6 = { aa 89 [2] 8e 87 [2] a5 ab [2] 8b 89 [2] 9f 92 [2] 90 88 [2] 8e 95 [2] 8c 94 [2] 97 92 [2] 8b 95 [2] 97 ba }

  condition:
    any of them
}