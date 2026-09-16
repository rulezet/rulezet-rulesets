rule TTP_XOR_QUAD_CurrentVersionRun_ff8e {
  strings:
    $key_ff8e = { ac e1 [2] 88 ef [2] a3 c3 [2] 8d e1 [2] 99 fa [2] 96 e0 [2] 88 fd [2] 8a fc [2] 91 fa [2] 8d fd [2] 91 d2 }

  condition:
    any of them
}