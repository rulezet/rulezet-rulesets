rule TTP_XOR_QUAD_CurrentVersionRun_b240 {
  strings:
    $key_b240 = { e1 2f [2] c5 21 [2] ee 0d [2] c0 2f [2] d4 34 [2] db 2e [2] c5 33 [2] c7 32 [2] dc 34 [2] c0 33 [2] dc 1c }

  condition:
    any of them
}