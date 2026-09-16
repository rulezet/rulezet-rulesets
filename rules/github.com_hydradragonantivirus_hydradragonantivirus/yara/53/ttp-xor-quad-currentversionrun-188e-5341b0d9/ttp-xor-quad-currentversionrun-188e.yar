rule TTP_XOR_QUAD_CurrentVersionRun_188e {
  strings:
    $key_188e = { 4b e1 [2] 6f ef [2] 44 c3 [2] 6a e1 [2] 7e fa [2] 71 e0 [2] 6f fd [2] 6d fc [2] 76 fa [2] 6a fd [2] 76 d2 }

  condition:
    any of them
}