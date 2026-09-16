rule TTP_XOR_QUAD_CurrentVersionRun_b290 {
  strings:
    $key_b290 = { e1 ff [2] c5 f1 [2] ee dd [2] c0 ff [2] d4 e4 [2] db fe [2] c5 e3 [2] c7 e2 [2] dc e4 [2] c0 e3 [2] dc cc }

  condition:
    any of them
}