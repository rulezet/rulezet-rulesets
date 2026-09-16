rule TTP_XOR_QUAD_CurrentVersionRun_c58e {
  strings:
    $key_c58e = { 96 e1 [2] b2 ef [2] 99 c3 [2] b7 e1 [2] a3 fa [2] ac e0 [2] b2 fd [2] b0 fc [2] ab fa [2] b7 fd [2] ab d2 }

  condition:
    any of them
}