rule TTP_XOR_QUAD_CurrentVersionRun_f8e6 {
  strings:
    $key_f8e6 = { ab 89 [2] 8f 87 [2] a4 ab [2] 8a 89 [2] 9e 92 [2] 91 88 [2] 8f 95 [2] 8d 94 [2] 96 92 [2] 8a 95 [2] 96 ba }

  condition:
    any of them
}