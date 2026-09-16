rule TTP_XOR_QUAD_CurrentVersionRun_b2fa {
  strings:
    $key_b2fa = { e1 95 [2] c5 9b [2] ee b7 [2] c0 95 [2] d4 8e [2] db 94 [2] c5 89 [2] c7 88 [2] dc 8e [2] c0 89 [2] dc a6 }

  condition:
    any of them
}