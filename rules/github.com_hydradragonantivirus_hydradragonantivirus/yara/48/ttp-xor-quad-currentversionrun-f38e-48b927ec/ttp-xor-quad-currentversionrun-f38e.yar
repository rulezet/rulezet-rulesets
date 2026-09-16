rule TTP_XOR_QUAD_CurrentVersionRun_f38e {
  strings:
    $key_f38e = { a0 e1 [2] 84 ef [2] af c3 [2] 81 e1 [2] 95 fa [2] 9a e0 [2] 84 fd [2] 86 fc [2] 9d fa [2] 81 fd [2] 9d d2 }

  condition:
    any of them
}