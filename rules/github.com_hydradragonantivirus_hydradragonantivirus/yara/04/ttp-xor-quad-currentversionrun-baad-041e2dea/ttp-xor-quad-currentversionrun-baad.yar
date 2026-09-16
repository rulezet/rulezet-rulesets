rule TTP_XOR_QUAD_CurrentVersionRun_baad {
  strings:
    $key_baad = { e9 c2 [2] cd cc [2] e6 e0 [2] c8 c2 [2] dc d9 [2] d3 c3 [2] cd de [2] cf df [2] d4 d9 [2] c8 de [2] d4 f1 }

  condition:
    any of them
}