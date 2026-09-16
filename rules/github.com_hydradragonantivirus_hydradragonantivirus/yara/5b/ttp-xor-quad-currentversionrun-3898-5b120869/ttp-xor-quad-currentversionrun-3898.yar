rule TTP_XOR_QUAD_CurrentVersionRun_3898 {
  strings:
    $key_3898 = { 6b f7 [2] 4f f9 [2] 64 d5 [2] 4a f7 [2] 5e ec [2] 51 f6 [2] 4f eb [2] 4d ea [2] 56 ec [2] 4a eb [2] 56 c4 }

  condition:
    any of them
}