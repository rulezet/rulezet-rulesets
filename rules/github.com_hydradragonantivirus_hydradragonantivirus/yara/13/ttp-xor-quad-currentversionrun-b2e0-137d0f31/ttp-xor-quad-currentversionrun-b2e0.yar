rule TTP_XOR_QUAD_CurrentVersionRun_b2e0 {
  strings:
    $key_b2e0 = { e1 8f [2] c5 81 [2] ee ad [2] c0 8f [2] d4 94 [2] db 8e [2] c5 93 [2] c7 92 [2] dc 94 [2] c0 93 [2] dc bc }

  condition:
    any of them
}