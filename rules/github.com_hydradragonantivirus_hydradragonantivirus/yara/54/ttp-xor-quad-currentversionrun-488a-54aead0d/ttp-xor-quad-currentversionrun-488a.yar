rule TTP_XOR_QUAD_CurrentVersionRun_488a {
  strings:
    $key_488a = { 1b e5 [2] 3f eb [2] 14 c7 [2] 3a e5 [2] 2e fe [2] 21 e4 [2] 3f f9 [2] 3d f8 [2] 26 fe [2] 3a f9 [2] 26 d6 }

  condition:
    any of them
}