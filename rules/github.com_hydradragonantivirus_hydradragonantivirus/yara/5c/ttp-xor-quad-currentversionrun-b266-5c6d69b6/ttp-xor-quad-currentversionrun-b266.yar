rule TTP_XOR_QUAD_CurrentVersionRun_b266 {
  strings:
    $key_b266 = { e1 09 [2] c5 07 [2] ee 2b [2] c0 09 [2] d4 12 [2] db 08 [2] c5 15 [2] c7 14 [2] dc 12 [2] c0 15 [2] dc 3a }

  condition:
    any of them
}