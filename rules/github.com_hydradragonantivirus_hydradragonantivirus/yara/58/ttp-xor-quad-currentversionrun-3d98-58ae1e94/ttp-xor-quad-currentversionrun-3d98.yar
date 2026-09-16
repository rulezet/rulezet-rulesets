rule TTP_XOR_QUAD_CurrentVersionRun_3d98 {
  strings:
    $key_3d98 = { 6e f7 [2] 4a f9 [2] 61 d5 [2] 4f f7 [2] 5b ec [2] 54 f6 [2] 4a eb [2] 48 ea [2] 53 ec [2] 4f eb [2] 53 c4 }

  condition:
    any of them
}