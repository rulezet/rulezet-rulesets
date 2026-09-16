rule TTP_XOR_QUAD_CurrentVersionRun_ed8e {
  strings:
    $key_ed8e = { be e1 [2] 9a ef [2] b1 c3 [2] 9f e1 [2] 8b fa [2] 84 e0 [2] 9a fd [2] 98 fc [2] 83 fa [2] 9f fd [2] 83 d2 }

  condition:
    any of them
}