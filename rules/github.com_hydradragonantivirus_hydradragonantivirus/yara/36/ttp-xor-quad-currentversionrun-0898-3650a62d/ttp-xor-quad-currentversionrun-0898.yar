rule TTP_XOR_QUAD_CurrentVersionRun_0898 {
  strings:
    $key_0898 = { 5b f7 [2] 7f f9 [2] 54 d5 [2] 7a f7 [2] 6e ec [2] 61 f6 [2] 7f eb [2] 7d ea [2] 66 ec [2] 7a eb [2] 66 c4 }

  condition:
    any of them
}