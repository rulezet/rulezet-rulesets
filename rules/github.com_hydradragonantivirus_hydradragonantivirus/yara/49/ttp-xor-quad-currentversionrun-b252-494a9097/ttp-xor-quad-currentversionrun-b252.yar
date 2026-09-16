rule TTP_XOR_QUAD_CurrentVersionRun_b252 {
  strings:
    $key_b252 = { e1 3d [2] c5 33 [2] ee 1f [2] c0 3d [2] d4 26 [2] db 3c [2] c5 21 [2] c7 20 [2] dc 26 [2] c0 21 [2] dc 0e }

  condition:
    any of them
}