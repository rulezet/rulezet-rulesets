rule TTP_XOR_QUAD_CurrentVersionRun_b24e {
  strings:
    $key_b24e = { e1 21 [2] c5 2f [2] ee 03 [2] c0 21 [2] d4 3a [2] db 20 [2] c5 3d [2] c7 3c [2] dc 3a [2] c0 3d [2] dc 12 }

  condition:
    any of them
}