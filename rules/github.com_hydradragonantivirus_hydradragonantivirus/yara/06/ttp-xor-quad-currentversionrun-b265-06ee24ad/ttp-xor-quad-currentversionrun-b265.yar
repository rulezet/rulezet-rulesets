rule TTP_XOR_QUAD_CurrentVersionRun_b265 {
  strings:
    $key_b265 = { e1 0a [2] c5 04 [2] ee 28 [2] c0 0a [2] d4 11 [2] db 0b [2] c5 16 [2] c7 17 [2] dc 11 [2] c0 16 [2] dc 39 }

  condition:
    any of them
}