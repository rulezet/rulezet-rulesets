rule TTP_XOR_QUAD_CurrentVersionRun_b25e {
  strings:
    $key_b25e = { e1 31 [2] c5 3f [2] ee 13 [2] c0 31 [2] d4 2a [2] db 30 [2] c5 2d [2] c7 2c [2] dc 2a [2] c0 2d [2] dc 02 }

  condition:
    any of them
}