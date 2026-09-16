rule TTP_XOR_QUAD_CurrentVersionRun_18a2 {
  strings:
    $key_18a2 = { 4b cd [2] 6f c3 [2] 44 ef [2] 6a cd [2] 7e d6 [2] 71 cc [2] 6f d1 [2] 6d d0 [2] 76 d6 [2] 6a d1 [2] 76 fe }

  condition:
    any of them
}