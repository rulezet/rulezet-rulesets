rule TTP_XOR_QUAD_CurrentVersionRun_b23d {
  strings:
    $key_b23d = { e1 52 [2] c5 5c [2] ee 70 [2] c0 52 [2] d4 49 [2] db 53 [2] c5 4e [2] c7 4f [2] dc 49 [2] c0 4e [2] dc 61 }

  condition:
    any of them
}