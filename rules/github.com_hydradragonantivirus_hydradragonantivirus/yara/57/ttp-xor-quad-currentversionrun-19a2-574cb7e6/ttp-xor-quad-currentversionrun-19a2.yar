rule TTP_XOR_QUAD_CurrentVersionRun_19a2 {
  strings:
    $key_19a2 = { 4a cd [2] 6e c3 [2] 45 ef [2] 6b cd [2] 7f d6 [2] 70 cc [2] 6e d1 [2] 6c d0 [2] 77 d6 [2] 6b d1 [2] 77 fe }

  condition:
    any of them
}