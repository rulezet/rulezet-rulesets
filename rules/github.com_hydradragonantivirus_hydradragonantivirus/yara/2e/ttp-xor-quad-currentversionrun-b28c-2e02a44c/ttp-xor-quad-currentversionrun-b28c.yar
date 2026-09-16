rule TTP_XOR_QUAD_CurrentVersionRun_b28c {
  strings:
    $key_b28c = { e1 e3 [2] c5 ed [2] ee c1 [2] c0 e3 [2] d4 f8 [2] db e2 [2] c5 ff [2] c7 fe [2] dc f8 [2] c0 ff [2] dc d0 }

  condition:
    any of them
}