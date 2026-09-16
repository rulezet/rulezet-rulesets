rule TTP_XOR_QUAD_CurrentVersionRun_b257 {
  strings:
    $key_b257 = { e1 38 [2] c5 36 [2] ee 1a [2] c0 38 [2] d4 23 [2] db 39 [2] c5 24 [2] c7 25 [2] dc 23 [2] c0 24 [2] dc 0b }

  condition:
    any of them
}