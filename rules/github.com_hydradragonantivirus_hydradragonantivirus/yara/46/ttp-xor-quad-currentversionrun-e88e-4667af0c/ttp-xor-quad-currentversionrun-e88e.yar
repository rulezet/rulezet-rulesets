rule TTP_XOR_QUAD_CurrentVersionRun_e88e {
  strings:
    $key_e88e = { bb e1 [2] 9f ef [2] b4 c3 [2] 9a e1 [2] 8e fa [2] 81 e0 [2] 9f fd [2] 9d fc [2] 86 fa [2] 9a fd [2] 86 d2 }

  condition:
    any of them
}