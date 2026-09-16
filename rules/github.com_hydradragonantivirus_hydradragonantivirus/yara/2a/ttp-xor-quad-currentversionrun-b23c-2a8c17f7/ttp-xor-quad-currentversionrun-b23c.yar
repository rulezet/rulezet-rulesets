rule TTP_XOR_QUAD_CurrentVersionRun_b23c {
  strings:
    $key_b23c = { e1 53 [2] c5 5d [2] ee 71 [2] c0 53 [2] d4 48 [2] db 52 [2] c5 4f [2] c7 4e [2] dc 48 [2] c0 4f [2] dc 60 }

  condition:
    any of them
}