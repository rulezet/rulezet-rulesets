rule TTP_XOR_QUAD_CurrentVersionRun_b23e {
  strings:
    $key_b23e = { e1 51 [2] c5 5f [2] ee 73 [2] c0 51 [2] d4 4a [2] db 50 [2] c5 4d [2] c7 4c [2] dc 4a [2] c0 4d [2] dc 62 }

  condition:
    any of them
}