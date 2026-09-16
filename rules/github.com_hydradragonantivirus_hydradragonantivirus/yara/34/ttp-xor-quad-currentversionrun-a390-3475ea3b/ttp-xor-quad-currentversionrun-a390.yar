rule TTP_XOR_QUAD_CurrentVersionRun_a390 {
  strings:
    $key_a390 = { f0 ff [2] d4 f1 [2] ff dd [2] d1 ff [2] c5 e4 [2] ca fe [2] d4 e3 [2] d6 e2 [2] cd e4 [2] d1 e3 [2] cd cc }

  condition:
    any of them
}