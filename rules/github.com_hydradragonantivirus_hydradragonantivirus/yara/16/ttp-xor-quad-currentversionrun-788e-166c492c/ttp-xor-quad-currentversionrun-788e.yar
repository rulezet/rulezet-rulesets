rule TTP_XOR_QUAD_CurrentVersionRun_788e {
  strings:
    $key_788e = { 2b e1 [2] 0f ef [2] 24 c3 [2] 0a e1 [2] 1e fa [2] 11 e0 [2] 0f fd [2] 0d fc [2] 16 fa [2] 0a fd [2] 16 d2 }

  condition:
    any of them
}