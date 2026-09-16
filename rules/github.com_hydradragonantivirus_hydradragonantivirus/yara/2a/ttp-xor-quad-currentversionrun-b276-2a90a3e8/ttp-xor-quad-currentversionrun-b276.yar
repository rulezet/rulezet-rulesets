rule TTP_XOR_QUAD_CurrentVersionRun_b276 {
  strings:
    $key_b276 = { e1 19 [2] c5 17 [2] ee 3b [2] c0 19 [2] d4 02 [2] db 18 [2] c5 05 [2] c7 04 [2] dc 02 [2] c0 05 [2] dc 2a }

  condition:
    any of them
}