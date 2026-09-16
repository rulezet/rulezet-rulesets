rule TTP_XOR_QUAD_CurrentVersionRun_488e {
  strings:
    $key_488e = { 1b e1 [2] 3f ef [2] 14 c3 [2] 3a e1 [2] 2e fa [2] 21 e0 [2] 3f fd [2] 3d fc [2] 26 fa [2] 3a fd [2] 26 d2 }

  condition:
    any of them
}