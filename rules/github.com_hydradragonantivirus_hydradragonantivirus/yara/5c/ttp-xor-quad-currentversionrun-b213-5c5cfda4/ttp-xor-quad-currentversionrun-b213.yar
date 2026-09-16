rule TTP_XOR_QUAD_CurrentVersionRun_b213 {
  strings:
    $key_b213 = { e1 7c [2] c5 72 [2] ee 5e [2] c0 7c [2] d4 67 [2] db 7d [2] c5 60 [2] c7 61 [2] dc 67 [2] c0 60 [2] dc 4f }

  condition:
    any of them
}