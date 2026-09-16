rule TTP_XOR_QUAD_CurrentVersionRun_248e {
  strings:
    $key_248e = { 77 e1 [2] 53 ef [2] 78 c3 [2] 56 e1 [2] 42 fa [2] 4d e0 [2] 53 fd [2] 51 fc [2] 4a fa [2] 56 fd [2] 4a d2 }

  condition:
    any of them
}