rule TTP_XOR_QUAD_CurrentVersionRun_b2fd {
  strings:
    $key_b2fd = { e1 92 [2] c5 9c [2] ee b0 [2] c0 92 [2] d4 89 [2] db 93 [2] c5 8e [2] c7 8f [2] dc 89 [2] c0 8e [2] dc a1 }

  condition:
    any of them
}