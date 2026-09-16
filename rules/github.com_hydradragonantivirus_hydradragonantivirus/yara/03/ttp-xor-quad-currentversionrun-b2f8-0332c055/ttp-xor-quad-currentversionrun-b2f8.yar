rule TTP_XOR_QUAD_CurrentVersionRun_b2f8 {
  strings:
    $key_b2f8 = { e1 97 [2] c5 99 [2] ee b5 [2] c0 97 [2] d4 8c [2] db 96 [2] c5 8b [2] c7 8a [2] dc 8c [2] c0 8b [2] dc a4 }

  condition:
    any of them
}