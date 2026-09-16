rule TTP_XOR_QUAD_CurrentVersionRun_08a2 {
  strings:
    $key_08a2 = { 5b cd [2] 7f c3 [2] 54 ef [2] 7a cd [2] 6e d6 [2] 61 cc [2] 7f d1 [2] 7d d0 [2] 66 d6 [2] 7a d1 [2] 66 fe }

  condition:
    any of them
}