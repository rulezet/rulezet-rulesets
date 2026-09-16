rule TTP_XOR_QUAD_CurrentVersionRun_d48e {
  strings:
    $key_d48e = { 87 e1 [2] a3 ef [2] 88 c3 [2] a6 e1 [2] b2 fa [2] bd e0 [2] a3 fd [2] a1 fc [2] ba fa [2] a6 fd [2] ba d2 }

  condition:
    any of them
}