rule TTP_XOR_QUAD_CurrentVersionRun_088e {
  strings:
    $key_088e = { 5b e1 [2] 7f ef [2] 54 c3 [2] 7a e1 [2] 6e fa [2] 61 e0 [2] 7f fd [2] 7d fc [2] 66 fa [2] 7a fd [2] 66 d2 }

  condition:
    any of them
}