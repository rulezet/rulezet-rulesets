rule TTP_XOR_QUAD_CurrentVersionRun_09a2 {
  strings:
    $key_09a2 = { 5a cd [2] 7e c3 [2] 55 ef [2] 7b cd [2] 6f d6 [2] 60 cc [2] 7e d1 [2] 7c d0 [2] 67 d6 [2] 7b d1 [2] 67 fe }

  condition:
    any of them
}