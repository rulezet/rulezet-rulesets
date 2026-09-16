rule TTP_XOR_QUAD_CurrentVersionRun_7296 {
  strings:
    $key_7296 = { 21 f9 [2] 05 f7 [2] 2e db [2] 00 f9 [2] 14 e2 [2] 1b f8 [2] 05 e5 [2] 07 e4 [2] 1c e2 [2] 00 e5 [2] 1c ca }

  condition:
    any of them
}