rule TTP_XOR_QUAD_CurrentVersionRun_c28e {
  strings:
    $key_c28e = { 91 e1 [2] b5 ef [2] 9e c3 [2] b0 e1 [2] a4 fa [2] ab e0 [2] b5 fd [2] b7 fc [2] ac fa [2] b0 fd [2] ac d2 }

  condition:
    any of them
}