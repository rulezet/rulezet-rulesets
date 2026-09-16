rule TTP_XOR_QUAD_CurrentVersionRun_ecbe {
  strings:
    $key_ecbe = { bf d1 [2] 9b df [2] b0 f3 [2] 9e d1 [2] 8a ca [2] 85 d0 [2] 9b cd [2] 99 cc [2] 82 ca [2] 9e cd [2] 82 e2 }

  condition:
    any of them
}