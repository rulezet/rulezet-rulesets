rule TTP_XOR_QUAD_CurrentVersionRun_2cbe {
  strings:
    $key_2cbe = { 7f d1 [2] 5b df [2] 70 f3 [2] 5e d1 [2] 4a ca [2] 45 d0 [2] 5b cd [2] 59 cc [2] 42 ca [2] 5e cd [2] 42 e2 }

  condition:
    any of them
}