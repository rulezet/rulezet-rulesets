rule TTP_XOR_QUAD_CurrentVersionRun_b21b {
  strings:
    $key_b21b = { e1 74 [2] c5 7a [2] ee 56 [2] c0 74 [2] d4 6f [2] db 75 [2] c5 68 [2] c7 69 [2] dc 6f [2] c0 68 [2] dc 47 }

  condition:
    any of them
}