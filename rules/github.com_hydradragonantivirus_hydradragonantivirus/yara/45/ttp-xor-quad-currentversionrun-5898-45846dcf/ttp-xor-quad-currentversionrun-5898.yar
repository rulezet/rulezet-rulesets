rule TTP_XOR_QUAD_CurrentVersionRun_5898 {
  strings:
    $key_5898 = { 0b f7 [2] 2f f9 [2] 04 d5 [2] 2a f7 [2] 3e ec [2] 31 f6 [2] 2f eb [2] 2d ea [2] 36 ec [2] 2a eb [2] 36 c4 }

  condition:
    any of them
}