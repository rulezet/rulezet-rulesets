rule TTP_XOR_QUAD_CurrentVersionRun_178e {
  strings:
    $key_178e = { 44 e1 [2] 60 ef [2] 4b c3 [2] 65 e1 [2] 71 fa [2] 7e e0 [2] 60 fd [2] 62 fc [2] 79 fa [2] 65 fd [2] 79 d2 }

  condition:
    any of them
}