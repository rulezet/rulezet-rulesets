rule TTP_XOR_QUAD_CurrentVersionRun_78a2 {
  strings:
    $key_78a2 = { 2b cd [2] 0f c3 [2] 24 ef [2] 0a cd [2] 1e d6 [2] 11 cc [2] 0f d1 [2] 0d d0 [2] 16 d6 [2] 0a d1 [2] 16 fe }

  condition:
    any of them
}