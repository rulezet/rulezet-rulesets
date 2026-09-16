rule TTP_XOR_QUAD_CurrentVersionRun_3d8e {
  strings:
    $key_3d8e = { 6e e1 [2] 4a ef [2] 61 c3 [2] 4f e1 [2] 5b fa [2] 54 e0 [2] 4a fd [2] 48 fc [2] 53 fa [2] 4f fd [2] 53 d2 }

  condition:
    any of them
}