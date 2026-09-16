rule TTP_XOR_QUAD_CurrentVersionRun_b25c {
  strings:
    $key_b25c = { e1 33 [2] c5 3d [2] ee 11 [2] c0 33 [2] d4 28 [2] db 32 [2] c5 2f [2] c7 2e [2] dc 28 [2] c0 2f [2] dc 00 }

  condition:
    any of them
}