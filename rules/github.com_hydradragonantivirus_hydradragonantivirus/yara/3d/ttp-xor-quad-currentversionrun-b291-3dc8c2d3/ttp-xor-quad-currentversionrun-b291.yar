rule TTP_XOR_QUAD_CurrentVersionRun_b291 {
  strings:
    $key_b291 = { e1 fe [2] c5 f0 [2] ee dc [2] c0 fe [2] d4 e5 [2] db ff [2] c5 e2 [2] c7 e3 [2] dc e5 [2] c0 e2 [2] dc cd }

  condition:
    any of them
}