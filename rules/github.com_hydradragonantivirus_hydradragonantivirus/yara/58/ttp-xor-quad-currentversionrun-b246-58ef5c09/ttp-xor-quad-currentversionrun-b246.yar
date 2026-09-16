rule TTP_XOR_QUAD_CurrentVersionRun_b246 {
  strings:
    $key_b246 = { e1 29 [2] c5 27 [2] ee 0b [2] c0 29 [2] d4 32 [2] db 28 [2] c5 35 [2] c7 34 [2] dc 32 [2] c0 35 [2] dc 1a }

  condition:
    any of them
}