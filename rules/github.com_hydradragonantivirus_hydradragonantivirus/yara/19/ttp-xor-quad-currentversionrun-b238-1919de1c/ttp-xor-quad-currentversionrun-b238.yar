rule TTP_XOR_QUAD_CurrentVersionRun_b238 {
  strings:
    $key_b238 = { e1 57 [2] c5 59 [2] ee 75 [2] c0 57 [2] d4 4c [2] db 56 [2] c5 4b [2] c7 4a [2] dc 4c [2] c0 4b [2] dc 64 }

  condition:
    any of them
}