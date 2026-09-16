rule TTP_XOR_QUAD_CurrentVersionRun_b295 {
  strings:
    $key_b295 = { e1 fa [2] c5 f4 [2] ee d8 [2] c0 fa [2] d4 e1 [2] db fb [2] c5 e6 [2] c7 e7 [2] dc e1 [2] c0 e6 [2] dc c9 }

  condition:
    any of them
}