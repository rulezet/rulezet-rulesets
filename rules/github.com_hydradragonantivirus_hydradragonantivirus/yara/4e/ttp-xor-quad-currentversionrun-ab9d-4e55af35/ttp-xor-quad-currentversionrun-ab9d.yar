rule TTP_XOR_QUAD_CurrentVersionRun_ab9d {
  strings:
    $key_ab9d = { f8 f2 [2] dc fc [2] f7 d0 [2] d9 f2 [2] cd e9 [2] c2 f3 [2] dc ee [2] de ef [2] c5 e9 [2] d9 ee [2] c5 c1 }

  condition:
    any of them
}