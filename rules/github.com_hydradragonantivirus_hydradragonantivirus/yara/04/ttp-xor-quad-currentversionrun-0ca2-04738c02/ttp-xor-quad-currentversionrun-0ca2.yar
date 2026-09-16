rule TTP_XOR_QUAD_CurrentVersionRun_0ca2 {
  strings:
    $key_0ca2 = { 5f cd [2] 7b c3 [2] 50 ef [2] 7e cd [2] 6a d6 [2] 65 cc [2] 7b d1 [2] 79 d0 [2] 62 d6 [2] 7e d1 [2] 62 fe }

  condition:
    any of them
}