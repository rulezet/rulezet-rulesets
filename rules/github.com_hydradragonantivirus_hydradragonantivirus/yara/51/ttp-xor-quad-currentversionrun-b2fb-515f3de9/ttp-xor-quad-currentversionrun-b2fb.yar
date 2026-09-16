rule TTP_XOR_QUAD_CurrentVersionRun_b2fb {
  strings:
    $key_b2fb = { e1 94 [2] c5 9a [2] ee b6 [2] c0 94 [2] d4 8f [2] db 95 [2] c5 88 [2] c7 89 [2] dc 8f [2] c0 88 [2] dc a7 }

  condition:
    any of them
}