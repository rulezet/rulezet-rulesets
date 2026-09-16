rule TTP_XOR_QUAD_CurrentVersionRun_ab98 {
  strings:
    $key_ab98 = { f8 f7 [2] dc f9 [2] f7 d5 [2] d9 f7 [2] cd ec [2] c2 f6 [2] dc eb [2] de ea [2] c5 ec [2] d9 eb [2] c5 c4 }

  condition:
    any of them
}