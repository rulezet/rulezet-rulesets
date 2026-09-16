rule TTP_XOR_QUAD_CurrentVersionRun_d78e {
  strings:
    $key_d78e = { 84 e1 [2] a0 ef [2] 8b c3 [2] a5 e1 [2] b1 fa [2] be e0 [2] a0 fd [2] a2 fc [2] b9 fa [2] a5 fd [2] b9 d2 }

  condition:
    any of them
}