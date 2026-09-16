rule TTP_XOR_QUAD_CurrentVersionRun_29e6 {
  strings:
    $key_29e6 = { 7a 89 [2] 5e 87 [2] 75 ab [2] 5b 89 [2] 4f 92 [2] 40 88 [2] 5e 95 [2] 5c 94 [2] 47 92 [2] 5b 95 [2] 47 ba }

  condition:
    any of them
}