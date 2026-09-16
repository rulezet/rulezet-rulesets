rule TTP_XOR_QUAD_CurrentVersionRun_f8a2 {
  strings:
    $key_f8a2 = { ab cd [2] 8f c3 [2] a4 ef [2] 8a cd [2] 9e d6 [2] 91 cc [2] 8f d1 [2] 8d d0 [2] 96 d6 [2] 8a d1 [2] 96 fe }

  condition:
    any of them
}