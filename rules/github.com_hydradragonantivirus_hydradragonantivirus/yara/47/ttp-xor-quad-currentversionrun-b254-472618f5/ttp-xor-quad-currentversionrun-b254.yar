rule TTP_XOR_QUAD_CurrentVersionRun_b254 {
  strings:
    $key_b254 = { e1 3b [2] c5 35 [2] ee 19 [2] c0 3b [2] d4 20 [2] db 3a [2] c5 27 [2] c7 26 [2] dc 20 [2] c0 27 [2] dc 08 }

  condition:
    any of them
}