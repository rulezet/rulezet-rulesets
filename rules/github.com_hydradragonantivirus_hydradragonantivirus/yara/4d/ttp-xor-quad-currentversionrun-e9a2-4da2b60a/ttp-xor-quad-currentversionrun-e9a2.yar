rule TTP_XOR_QUAD_CurrentVersionRun_e9a2 {
  strings:
    $key_e9a2 = { ba cd [2] 9e c3 [2] b5 ef [2] 9b cd [2] 8f d6 [2] 80 cc [2] 9e d1 [2] 9c d0 [2] 87 d6 [2] 9b d1 [2] 87 fe }

  condition:
    any of them
}