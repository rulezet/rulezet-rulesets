rule TTP_XOR_QUAD_CurrentVersionRun_4da2 {
  strings:
    $key_4da2 = { 1e cd [2] 3a c3 [2] 11 ef [2] 3f cd [2] 2b d6 [2] 24 cc [2] 3a d1 [2] 38 d0 [2] 23 d6 [2] 3f d1 [2] 23 fe }

  condition:
    any of them
}