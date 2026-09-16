rule TTP_XOR_QUAD_CurrentVersionRun_bbe6 {
  strings:
    $key_bbe6 = { e8 89 [2] cc 87 [2] e7 ab [2] c9 89 [2] dd 92 [2] d2 88 [2] cc 95 [2] ce 94 [2] d5 92 [2] c9 95 [2] d5 ba }

  condition:
    any of them
}