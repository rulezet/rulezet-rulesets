rule TTP_XOR_QUAD_CurrentVersionRun_b2f4 {
  strings:
    $key_b2f4 = { e1 9b [2] c5 95 [2] ee b9 [2] c0 9b [2] d4 80 [2] db 9a [2] c5 87 [2] c7 86 [2] dc 80 [2] c0 87 [2] dc a8 }

  condition:
    any of them
}