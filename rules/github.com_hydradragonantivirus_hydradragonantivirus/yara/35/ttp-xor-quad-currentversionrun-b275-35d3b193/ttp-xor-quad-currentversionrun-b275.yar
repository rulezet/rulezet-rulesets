rule TTP_XOR_QUAD_CurrentVersionRun_b275 {
  strings:
    $key_b275 = { e1 1a [2] c5 14 [2] ee 38 [2] c0 1a [2] d4 01 [2] db 1b [2] c5 06 [2] c7 07 [2] dc 01 [2] c0 06 [2] dc 29 }

  condition:
    any of them
}