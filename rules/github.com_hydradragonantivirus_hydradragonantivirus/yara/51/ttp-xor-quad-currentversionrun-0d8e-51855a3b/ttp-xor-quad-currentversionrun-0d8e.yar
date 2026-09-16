rule TTP_XOR_QUAD_CurrentVersionRun_0d8e {
  strings:
    $key_0d8e = { 5e e1 [2] 7a ef [2] 51 c3 [2] 7f e1 [2] 6b fa [2] 64 e0 [2] 7a fd [2] 78 fc [2] 63 fa [2] 7f fd [2] 63 d2 }

  condition:
    any of them
}