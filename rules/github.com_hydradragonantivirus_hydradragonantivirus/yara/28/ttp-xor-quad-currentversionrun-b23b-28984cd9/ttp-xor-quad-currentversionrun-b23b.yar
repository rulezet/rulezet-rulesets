rule TTP_XOR_QUAD_CurrentVersionRun_b23b {
  strings:
    $key_b23b = { e1 54 [2] c5 5a [2] ee 76 [2] c0 54 [2] d4 4f [2] db 55 [2] c5 48 [2] c7 49 [2] dc 4f [2] c0 48 [2] dc 67 }

  condition:
    any of them
}