rule TTP_XOR_QUAD_CurrentVersionRun_eb8e {
  strings:
    $key_eb8e = { b8 e1 [2] 9c ef [2] b7 c3 [2] 99 e1 [2] 8d fa [2] 82 e0 [2] 9c fd [2] 9e fc [2] 85 fa [2] 99 fd [2] 85 d2 }

  condition:
    any of them
}