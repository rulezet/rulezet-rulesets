rule TTP_XOR_QUAD_CurrentVersionRun_5cbe {
  strings:
    $key_5cbe = { 0f d1 [2] 2b df [2] 00 f3 [2] 2e d1 [2] 3a ca [2] 35 d0 [2] 2b cd [2] 29 cc [2] 32 ca [2] 2e cd [2] 32 e2 }

  condition:
    any of them
}