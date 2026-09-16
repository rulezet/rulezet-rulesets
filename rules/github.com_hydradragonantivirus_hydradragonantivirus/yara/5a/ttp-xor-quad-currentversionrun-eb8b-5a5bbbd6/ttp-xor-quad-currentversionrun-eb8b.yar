rule TTP_XOR_QUAD_CurrentVersionRun_eb8b {
  strings:
    $key_eb8b = { b8 e4 [2] 9c ea [2] b7 c6 [2] 99 e4 [2] 8d ff [2] 82 e5 [2] 9c f8 [2] 9e f9 [2] 85 ff [2] 99 f8 [2] 85 d7 }

  condition:
    any of them
}