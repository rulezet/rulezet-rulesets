rule TTP_XOR_QUAD_CurrentVersionRun_eb8a {
  strings:
    $key_eb8a = { b8 e5 [2] 9c eb [2] b7 c7 [2] 99 e5 [2] 8d fe [2] 82 e4 [2] 9c f9 [2] 9e f8 [2] 85 fe [2] 99 f9 [2] 85 d6 }

  condition:
    any of them
}