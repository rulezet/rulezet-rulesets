rule TTP_XOR_QUAD_CurrentVersionRun_b234 {
  strings:
    $key_b234 = { e1 5b [2] c5 55 [2] ee 79 [2] c0 5b [2] d4 40 [2] db 5a [2] c5 47 [2] c7 46 [2] dc 40 [2] c0 47 [2] dc 68 }

  condition:
    any of them
}