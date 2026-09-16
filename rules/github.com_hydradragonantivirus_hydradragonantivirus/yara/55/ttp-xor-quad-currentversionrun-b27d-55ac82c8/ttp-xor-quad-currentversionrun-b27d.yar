rule TTP_XOR_QUAD_CurrentVersionRun_b27d {
  strings:
    $key_b27d = { e1 12 [2] c5 1c [2] ee 30 [2] c0 12 [2] d4 09 [2] db 13 [2] c5 0e [2] c7 0f [2] dc 09 [2] c0 0e [2] dc 21 }

  condition:
    any of them
}