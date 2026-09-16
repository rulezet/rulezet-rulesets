rule TTP_XOR_QUAD_CurrentVersionRun_1984 {
  strings:
    $key_1984 = { 4a eb [2] 6e e5 [2] 45 c9 [2] 6b eb [2] 7f f0 [2] 70 ea [2] 6e f7 [2] 6c f6 [2] 77 f0 [2] 6b f7 [2] 77 d8 }

  condition:
    any of them
}