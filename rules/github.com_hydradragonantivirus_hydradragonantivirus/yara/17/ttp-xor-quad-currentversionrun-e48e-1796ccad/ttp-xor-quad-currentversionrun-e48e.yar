rule TTP_XOR_QUAD_CurrentVersionRun_e48e {
  strings:
    $key_e48e = { b7 e1 [2] 93 ef [2] b8 c3 [2] 96 e1 [2] 82 fa [2] 8d e0 [2] 93 fd [2] 91 fc [2] 8a fa [2] 96 fd [2] 8a d2 }

  condition:
    any of them
}