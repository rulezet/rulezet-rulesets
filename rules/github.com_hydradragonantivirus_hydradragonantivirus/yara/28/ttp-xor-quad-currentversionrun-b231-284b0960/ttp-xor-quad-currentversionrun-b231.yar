rule TTP_XOR_QUAD_CurrentVersionRun_b231 {
  strings:
    $key_b231 = { e1 5e [2] c5 50 [2] ee 7c [2] c0 5e [2] d4 45 [2] db 5f [2] c5 42 [2] c7 43 [2] dc 45 [2] c0 42 [2] dc 6d }

  condition:
    any of them
}