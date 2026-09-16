rule TTP_XOR_QUAD_CurrentVersionRun_668e {
  strings:
    $key_668e = { 35 e1 [2] 11 ef [2] 3a c3 [2] 14 e1 [2] 00 fa [2] 0f e0 [2] 11 fd [2] 13 fc [2] 08 fa [2] 14 fd [2] 08 d2 }

  condition:
    any of them
}