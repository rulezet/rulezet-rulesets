rule TTP_XOR_QUAD_CurrentVersionRun_088a {
  strings:
    $key_088a = { 5b e5 [2] 7f eb [2] 54 c7 [2] 7a e5 [2] 6e fe [2] 61 e4 [2] 7f f9 [2] 7d f8 [2] 66 fe [2] 7a f9 [2] 66 d6 }

  condition:
    any of them
}