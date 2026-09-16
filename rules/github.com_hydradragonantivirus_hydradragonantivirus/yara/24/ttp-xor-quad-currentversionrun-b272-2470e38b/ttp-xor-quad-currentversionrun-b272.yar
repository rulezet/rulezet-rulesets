rule TTP_XOR_QUAD_CurrentVersionRun_b272 {
  strings:
    $key_b272 = { e1 1d [2] c5 13 [2] ee 3f [2] c0 1d [2] d4 06 [2] db 1c [2] c5 01 [2] c7 00 [2] dc 06 [2] c0 01 [2] dc 2e }

  condition:
    any of them
}