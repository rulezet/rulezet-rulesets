rule TTP_XOR_QUAD_CurrentVersionRun_f88b {
  strings:
    $key_f88b = { ab e4 [2] 8f ea [2] a4 c6 [2] 8a e4 [2] 9e ff [2] 91 e5 [2] 8f f8 [2] 8d f9 [2] 96 ff [2] 8a f8 [2] 96 d7 }

  condition:
    any of them
}