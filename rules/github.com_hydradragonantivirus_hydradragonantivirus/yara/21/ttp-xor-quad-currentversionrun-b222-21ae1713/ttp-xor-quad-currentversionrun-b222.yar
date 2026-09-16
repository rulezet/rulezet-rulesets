rule TTP_XOR_QUAD_CurrentVersionRun_b222 {
  strings:
    $key_b222 = { e1 4d [2] c5 43 [2] ee 6f [2] c0 4d [2] d4 56 [2] db 4c [2] c5 51 [2] c7 50 [2] dc 56 [2] c0 51 [2] dc 7e }

  condition:
    any of them
}