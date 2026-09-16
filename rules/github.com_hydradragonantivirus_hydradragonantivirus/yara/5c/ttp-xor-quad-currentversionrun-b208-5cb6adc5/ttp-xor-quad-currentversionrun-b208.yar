rule TTP_XOR_QUAD_CurrentVersionRun_b208 {
  strings:
    $key_b208 = { e1 67 [2] c5 69 [2] ee 45 [2] c0 67 [2] d4 7c [2] db 66 [2] c5 7b [2] c7 7a [2] dc 7c [2] c0 7b [2] dc 54 }

  condition:
    any of them
}