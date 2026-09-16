rule TTP_XOR_QUAD_CurrentVersionRun_ad8d {
  strings:
    $key_ad8d = { fe e2 [2] da ec [2] f1 c0 [2] df e2 [2] cb f9 [2] c4 e3 [2] da fe [2] d8 ff [2] c3 f9 [2] df fe [2] c3 d1 }

  condition:
    any of them
}