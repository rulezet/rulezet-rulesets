rule TTP_XOR_QUAD_CurrentVersionRun_038e {
  strings:
    $key_038e = { 50 e1 [2] 74 ef [2] 5f c3 [2] 71 e1 [2] 65 fa [2] 6a e0 [2] 74 fd [2] 76 fc [2] 6d fa [2] 71 fd [2] 6d d2 }

  condition:
    any of them
}