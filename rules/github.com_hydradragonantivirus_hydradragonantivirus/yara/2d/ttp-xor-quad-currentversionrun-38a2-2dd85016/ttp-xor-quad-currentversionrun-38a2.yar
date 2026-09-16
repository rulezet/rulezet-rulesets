rule TTP_XOR_QUAD_CurrentVersionRun_38a2 {
  strings:
    $key_38a2 = { 6b cd [2] 4f c3 [2] 64 ef [2] 4a cd [2] 5e d6 [2] 51 cc [2] 4f d1 [2] 4d d0 [2] 56 d6 [2] 4a d1 [2] 56 fe }

  condition:
    any of them
}