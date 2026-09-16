rule TTP_XOR_QUAD_CurrentVersionRun_068e {
  strings:
    $key_068e = { 55 e1 [2] 71 ef [2] 5a c3 [2] 74 e1 [2] 60 fa [2] 6f e0 [2] 71 fd [2] 73 fc [2] 68 fa [2] 74 fd [2] 68 d2 }

  condition:
    any of them
}