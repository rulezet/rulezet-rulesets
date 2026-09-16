rule TTP_XOR_QUAD_CurrentVersionRun_1898 {
  strings:
    $key_1898 = { 4b f7 [2] 6f f9 [2] 44 d5 [2] 6a f7 [2] 7e ec [2] 71 f6 [2] 6f eb [2] 6d ea [2] 76 ec [2] 6a eb [2] 76 c4 }

  condition:
    any of them
}