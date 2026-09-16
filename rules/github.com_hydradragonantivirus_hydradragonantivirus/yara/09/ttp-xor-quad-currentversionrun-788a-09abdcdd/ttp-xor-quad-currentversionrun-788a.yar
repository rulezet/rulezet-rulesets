rule TTP_XOR_QUAD_CurrentVersionRun_788a {
  strings:
    $key_788a = { 2b e5 [2] 0f eb [2] 24 c7 [2] 0a e5 [2] 1e fe [2] 11 e4 [2] 0f f9 [2] 0d f8 [2] 16 fe [2] 0a f9 [2] 16 d6 }

  condition:
    any of them
}