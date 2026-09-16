rule TTP_XOR_QUAD_CurrentVersionRun_b269 {
  strings:
    $key_b269 = { e1 06 [2] c5 08 [2] ee 24 [2] c0 06 [2] d4 1d [2] db 07 [2] c5 1a [2] c7 1b [2] dc 1d [2] c0 1a [2] dc 35 }

  condition:
    any of them
}