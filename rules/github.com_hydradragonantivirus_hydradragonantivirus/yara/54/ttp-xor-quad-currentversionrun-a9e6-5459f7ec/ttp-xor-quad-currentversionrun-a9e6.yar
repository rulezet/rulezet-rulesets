rule TTP_XOR_QUAD_CurrentVersionRun_a9e6 {
  strings:
    $key_a9e6 = { fa 89 [2] de 87 [2] f5 ab [2] db 89 [2] cf 92 [2] c0 88 [2] de 95 [2] dc 94 [2] c7 92 [2] db 95 [2] c7 ba }

  condition:
    any of them
}