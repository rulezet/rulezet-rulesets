rule TTP_XOR_QUAD_CurrentVersionRun_b255 {
  strings:
    $key_b255 = { e1 3a [2] c5 34 [2] ee 18 [2] c0 3a [2] d4 21 [2] db 3b [2] c5 26 [2] c7 27 [2] dc 21 [2] c0 26 [2] dc 09 }

  condition:
    any of them
}