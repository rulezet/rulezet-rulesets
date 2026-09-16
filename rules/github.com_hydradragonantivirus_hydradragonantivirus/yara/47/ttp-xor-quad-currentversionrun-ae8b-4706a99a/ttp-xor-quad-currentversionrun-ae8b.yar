rule TTP_XOR_QUAD_CurrentVersionRun_ae8b {
  strings:
    $key_ae8b = { fd e4 [2] d9 ea [2] f2 c6 [2] dc e4 [2] c8 ff [2] c7 e5 [2] d9 f8 [2] db f9 [2] c0 ff [2] dc f8 [2] c0 d7 }

  condition:
    any of them
}