rule TTP_XOR_QUAD_CurrentVersionRun_b279 {
  strings:
    $key_b279 = { e1 16 [2] c5 18 [2] ee 34 [2] c0 16 [2] d4 0d [2] db 17 [2] c5 0a [2] c7 0b [2] dc 0d [2] c0 0a [2] dc 25 }

  condition:
    any of them
}