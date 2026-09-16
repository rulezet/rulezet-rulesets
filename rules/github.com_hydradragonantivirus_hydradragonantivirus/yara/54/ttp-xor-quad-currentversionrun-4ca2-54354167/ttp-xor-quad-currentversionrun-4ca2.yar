rule TTP_XOR_QUAD_CurrentVersionRun_4ca2 {
  strings:
    $key_4ca2 = { 1f cd [2] 3b c3 [2] 10 ef [2] 3e cd [2] 2a d6 [2] 25 cc [2] 3b d1 [2] 39 d0 [2] 22 d6 [2] 3e d1 [2] 22 fe }

  condition:
    any of them
}