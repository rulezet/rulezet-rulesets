rule TTP_XOR_QUAD_CurrentVersionRun_b248 {
  strings:
    $key_b248 = { e1 27 [2] c5 29 [2] ee 05 [2] c0 27 [2] d4 3c [2] db 26 [2] c5 3b [2] c7 3a [2] dc 3c [2] c0 3b [2] dc 14 }

  condition:
    any of them
}