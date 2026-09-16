rule TTP_XOR_QUAD_CurrentVersionRun_b215 {
  strings:
    $key_b215 = { e1 7a [2] c5 74 [2] ee 58 [2] c0 7a [2] d4 61 [2] db 7b [2] c5 66 [2] c7 67 [2] dc 61 [2] c0 66 [2] dc 49 }

  condition:
    any of them
}