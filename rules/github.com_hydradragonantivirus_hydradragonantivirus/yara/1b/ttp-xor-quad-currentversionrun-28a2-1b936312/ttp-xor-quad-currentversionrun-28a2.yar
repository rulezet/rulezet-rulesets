rule TTP_XOR_QUAD_CurrentVersionRun_28a2 {
  strings:
    $key_28a2 = { 7b cd [2] 5f c3 [2] 74 ef [2] 5a cd [2] 4e d6 [2] 41 cc [2] 5f d1 [2] 5d d0 [2] 46 d6 [2] 5a d1 [2] 46 fe }

  condition:
    any of them
}