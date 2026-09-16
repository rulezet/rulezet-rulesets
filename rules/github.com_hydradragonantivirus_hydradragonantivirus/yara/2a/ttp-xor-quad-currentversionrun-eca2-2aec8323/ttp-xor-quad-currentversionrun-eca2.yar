rule TTP_XOR_QUAD_CurrentVersionRun_eca2 {
  strings:
    $key_eca2 = { bf cd [2] 9b c3 [2] b0 ef [2] 9e cd [2] 8a d6 [2] 85 cc [2] 9b d1 [2] 99 d0 [2] 82 d6 [2] 9e d1 [2] 82 fe }

  condition:
    any of them
}