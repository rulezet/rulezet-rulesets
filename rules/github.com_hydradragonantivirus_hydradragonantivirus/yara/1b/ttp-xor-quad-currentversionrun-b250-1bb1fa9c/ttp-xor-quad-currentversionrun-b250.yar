rule TTP_XOR_QUAD_CurrentVersionRun_b250 {
  strings:
    $key_b250 = { e1 3f [2] c5 31 [2] ee 1d [2] c0 3f [2] d4 24 [2] db 3e [2] c5 23 [2] c7 22 [2] dc 24 [2] c0 23 [2] dc 0c }

  condition:
    any of them
}