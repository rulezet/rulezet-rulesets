rule TTP_XOR_QUAD_CurrentVersionRun_ab9f {
  strings:
    $key_ab9f = { f8 f0 [2] dc fe [2] f7 d2 [2] d9 f0 [2] cd eb [2] c2 f1 [2] dc ec [2] de ed [2] c5 eb [2] d9 ec [2] c5 c3 }

  condition:
    any of them
}