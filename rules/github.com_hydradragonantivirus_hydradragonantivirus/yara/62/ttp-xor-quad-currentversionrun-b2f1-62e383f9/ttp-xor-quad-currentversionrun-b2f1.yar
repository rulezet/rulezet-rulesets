rule TTP_XOR_QUAD_CurrentVersionRun_b2f1 {
  strings:
    $key_b2f1 = { e1 9e [2] c5 90 [2] ee bc [2] c0 9e [2] d4 85 [2] db 9f [2] c5 82 [2] c7 83 [2] dc 85 [2] c0 82 [2] dc ad }

  condition:
    any of them
}