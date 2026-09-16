rule TTP_XOR_QUAD_CurrentVersionRun_b27e {
  strings:
    $key_b27e = { e1 11 [2] c5 1f [2] ee 33 [2] c0 11 [2] d4 0a [2] db 10 [2] c5 0d [2] c7 0c [2] dc 0a [2] c0 0d [2] dc 22 }

  condition:
    any of them
}