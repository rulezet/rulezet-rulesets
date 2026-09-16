rule TTP_XOR_QUAD_CurrentVersionRun_b25a {
  strings:
    $key_b25a = { e1 35 [2] c5 3b [2] ee 17 [2] c0 35 [2] d4 2e [2] db 34 [2] c5 29 [2] c7 28 [2] dc 2e [2] c0 29 [2] dc 06 }

  condition:
    any of them
}