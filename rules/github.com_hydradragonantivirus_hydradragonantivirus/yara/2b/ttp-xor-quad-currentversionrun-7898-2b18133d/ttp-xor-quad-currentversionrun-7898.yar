rule TTP_XOR_QUAD_CurrentVersionRun_7898 {
  strings:
    $key_7898 = { 2b f7 [2] 0f f9 [2] 24 d5 [2] 0a f7 [2] 1e ec [2] 11 f6 [2] 0f eb [2] 0d ea [2] 16 ec [2] 0a eb [2] 16 c4 }

  condition:
    any of them
}