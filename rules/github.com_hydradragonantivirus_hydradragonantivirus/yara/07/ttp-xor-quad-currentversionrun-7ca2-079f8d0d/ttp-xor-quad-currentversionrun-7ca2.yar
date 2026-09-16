rule TTP_XOR_QUAD_CurrentVersionRun_7ca2 {
  strings:
    $key_7ca2 = { 2f cd [2] 0b c3 [2] 20 ef [2] 0e cd [2] 1a d6 [2] 15 cc [2] 0b d1 [2] 09 d0 [2] 12 d6 [2] 0e d1 [2] 12 fe }

  condition:
    any of them
}