rule TTP_XOR_QUAD_CurrentVersionRun_59a2 {
  strings:
    $key_59a2 = { 0a cd [2] 2e c3 [2] 05 ef [2] 2b cd [2] 3f d6 [2] 30 cc [2] 2e d1 [2] 2c d0 [2] 37 d6 [2] 2b d1 [2] 37 fe }

  condition:
    any of them
}