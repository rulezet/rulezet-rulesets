rule TTP_XOR_QUAD_CurrentVersionRun_688e {
  strings:
    $key_688e = { 3b e1 [2] 1f ef [2] 34 c3 [2] 1a e1 [2] 0e fa [2] 01 e0 [2] 1f fd [2] 1d fc [2] 06 fa [2] 1a fd [2] 06 d2 }

  condition:
    any of them
}