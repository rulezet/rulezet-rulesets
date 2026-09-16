rule TTP_XOR_QUAD_CurrentVersionRun_b206 {
  strings:
    $key_b206 = { e1 69 [2] c5 67 [2] ee 4b [2] c0 69 [2] d4 72 [2] db 68 [2] c5 75 [2] c7 74 [2] dc 72 [2] c0 75 [2] dc 5a }

  condition:
    any of them
}