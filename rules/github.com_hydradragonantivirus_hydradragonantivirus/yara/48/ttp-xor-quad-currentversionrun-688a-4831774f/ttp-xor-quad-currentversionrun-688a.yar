rule TTP_XOR_QUAD_CurrentVersionRun_688a {
  strings:
    $key_688a = { 3b e5 [2] 1f eb [2] 34 c7 [2] 1a e5 [2] 0e fe [2] 01 e4 [2] 1f f9 [2] 1d f8 [2] 06 fe [2] 1a f9 [2] 06 d6 }

  condition:
    any of them
}