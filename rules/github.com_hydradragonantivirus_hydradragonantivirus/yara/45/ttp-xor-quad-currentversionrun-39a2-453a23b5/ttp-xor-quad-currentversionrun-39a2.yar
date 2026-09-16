rule TTP_XOR_QUAD_CurrentVersionRun_39a2 {
  strings:
    $key_39a2 = { 6a cd [2] 4e c3 [2] 65 ef [2] 4b cd [2] 5f d6 [2] 50 cc [2] 4e d1 [2] 4c d0 [2] 57 d6 [2] 4b d1 [2] 57 fe }

  condition:
    any of them
}