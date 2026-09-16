rule TTP_XOR_QUAD_CurrentVersionRun_b237 {
  strings:
    $key_b237 = { e1 58 [2] c5 56 [2] ee 7a [2] c0 58 [2] d4 43 [2] db 59 [2] c5 44 [2] c7 45 [2] dc 43 [2] c0 44 [2] dc 6b }

  condition:
    any of them
}