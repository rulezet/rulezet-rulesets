rule TTP_XOR_QUAD_CurrentVersionRun_288b {
  strings:
    $key_288b = { 7b e4 [2] 5f ea [2] 74 c6 [2] 5a e4 [2] 4e ff [2] 41 e5 [2] 5f f8 [2] 5d f9 [2] 46 ff [2] 5a f8 [2] 46 d7 }

  condition:
    any of them
}