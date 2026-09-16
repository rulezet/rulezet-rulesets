rule TTP_XOR_QUAD_CurrentVersionRun_3f8e {
  strings:
    $key_3f8e = { 6c e1 [2] 48 ef [2] 63 c3 [2] 4d e1 [2] 59 fa [2] 56 e0 [2] 48 fd [2] 4a fc [2] 51 fa [2] 4d fd [2] 51 d2 }

  condition:
    any of them
}