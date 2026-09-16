rule TTP_XOR_QUAD_CurrentVersionRun_b22c {
  strings:
    $key_b22c = { e1 43 [2] c5 4d [2] ee 61 [2] c0 43 [2] d4 58 [2] db 42 [2] c5 5f [2] c7 5e [2] dc 58 [2] c0 5f [2] dc 70 }

  condition:
    any of them
}