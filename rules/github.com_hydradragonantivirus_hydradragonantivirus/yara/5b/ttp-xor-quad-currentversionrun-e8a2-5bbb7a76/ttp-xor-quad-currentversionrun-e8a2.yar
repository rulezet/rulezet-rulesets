rule TTP_XOR_QUAD_CurrentVersionRun_e8a2 {
  strings:
    $key_e8a2 = { bb cd [2] 9f c3 [2] b4 ef [2] 9a cd [2] 8e d6 [2] 81 cc [2] 9f d1 [2] 9d d0 [2] 86 d6 [2] 9a d1 [2] 86 fe }

  condition:
    any of them
}