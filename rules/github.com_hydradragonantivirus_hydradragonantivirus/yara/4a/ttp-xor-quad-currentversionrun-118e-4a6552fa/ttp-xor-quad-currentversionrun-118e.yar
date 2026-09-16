rule TTP_XOR_QUAD_CurrentVersionRun_118e {
  strings:
    $key_118e = { 42 e1 [2] 66 ef [2] 4d c3 [2] 63 e1 [2] 77 fa [2] 78 e0 [2] 66 fd [2] 64 fc [2] 7f fa [2] 63 fd [2] 7f d2 }

  condition:
    any of them
}