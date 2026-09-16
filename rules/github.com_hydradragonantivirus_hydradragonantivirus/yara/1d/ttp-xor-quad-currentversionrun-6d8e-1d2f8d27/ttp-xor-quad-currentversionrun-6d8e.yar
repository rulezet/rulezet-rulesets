rule TTP_XOR_QUAD_CurrentVersionRun_6d8e {
  strings:
    $key_6d8e = { 3e e1 [2] 1a ef [2] 31 c3 [2] 1f e1 [2] 0b fa [2] 04 e0 [2] 1a fd [2] 18 fc [2] 03 fa [2] 1f fd [2] 03 d2 }

  condition:
    any of them
}