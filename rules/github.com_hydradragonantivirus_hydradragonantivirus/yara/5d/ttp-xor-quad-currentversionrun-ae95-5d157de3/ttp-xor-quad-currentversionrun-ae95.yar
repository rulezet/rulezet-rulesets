rule TTP_XOR_QUAD_CurrentVersionRun_ae95 {
  strings:
    $key_ae95 = { fd fa [2] d9 f4 [2] f2 d8 [2] dc fa [2] c8 e1 [2] c7 fb [2] d9 e6 [2] db e7 [2] c0 e1 [2] dc e6 [2] c0 c9 }

  condition:
    any of them
}