rule TTP_XOR_QUAD_CurrentVersionRun_b2f9 {
  strings:
    $key_b2f9 = { e1 96 [2] c5 98 [2] ee b4 [2] c0 96 [2] d4 8d [2] db 97 [2] c5 8a [2] c7 8b [2] dc 8d [2] c0 8a [2] dc a5 }

  condition:
    any of them
}