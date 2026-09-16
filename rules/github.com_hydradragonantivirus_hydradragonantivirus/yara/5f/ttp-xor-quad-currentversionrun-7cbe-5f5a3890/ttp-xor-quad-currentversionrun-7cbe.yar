rule TTP_XOR_QUAD_CurrentVersionRun_7cbe {
  strings:
    $key_7cbe = { 2f d1 [2] 0b df [2] 20 f3 [2] 0e d1 [2] 1a ca [2] 15 d0 [2] 0b cd [2] 09 cc [2] 12 ca [2] 0e cd [2] 12 e2 }

  condition:
    any of them
}