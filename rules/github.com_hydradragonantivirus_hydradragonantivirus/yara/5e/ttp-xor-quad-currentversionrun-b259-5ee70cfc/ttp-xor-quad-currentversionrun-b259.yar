rule TTP_XOR_QUAD_CurrentVersionRun_b259 {
  strings:
    $key_b259 = { e1 36 [2] c5 38 [2] ee 14 [2] c0 36 [2] d4 2d [2] db 37 [2] c5 2a [2] c7 2b [2] dc 2d [2] c0 2a [2] dc 05 }

  condition:
    any of them
}