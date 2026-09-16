rule TTP_XOR_QUAD_CurrentVersionRun_7297 {
  strings:
    $key_7297 = { 21 f8 [2] 05 f6 [2] 2e da [2] 00 f8 [2] 14 e3 [2] 1b f9 [2] 05 e4 [2] 07 e5 [2] 1c e3 [2] 00 e4 [2] 1c cb }

  condition:
    any of them
}