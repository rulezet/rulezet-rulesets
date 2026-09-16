rule TTP_XOR_QUAD_CurrentVersionRun_4cbe {
  strings:
    $key_4cbe = { 1f d1 [2] 3b df [2] 10 f3 [2] 3e d1 [2] 2a ca [2] 25 d0 [2] 3b cd [2] 39 cc [2] 22 ca [2] 3e cd [2] 22 e2 }

  condition:
    any of them
}