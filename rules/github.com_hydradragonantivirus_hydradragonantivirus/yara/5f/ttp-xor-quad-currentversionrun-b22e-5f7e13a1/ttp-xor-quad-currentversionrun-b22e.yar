rule TTP_XOR_QUAD_CurrentVersionRun_b22e {
  strings:
    $key_b22e = { e1 41 [2] c5 4f [2] ee 63 [2] c0 41 [2] d4 5a [2] db 40 [2] c5 5d [2] c7 5c [2] dc 5a [2] c0 5d [2] dc 72 }

  condition:
    any of them
}