rule TTP_XOR_QUAD_CurrentVersionRun_ab91 {
  strings:
    $key_ab91 = { f8 fe [2] dc f0 [2] f7 dc [2] d9 fe [2] cd e5 [2] c2 ff [2] dc e2 [2] de e3 [2] c5 e5 [2] d9 e2 [2] c5 cd }

  condition:
    any of them
}