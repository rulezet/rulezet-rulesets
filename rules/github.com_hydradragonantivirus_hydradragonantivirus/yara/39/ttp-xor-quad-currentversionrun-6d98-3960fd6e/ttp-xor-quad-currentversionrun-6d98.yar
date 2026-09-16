rule TTP_XOR_QUAD_CurrentVersionRun_6d98 {
  strings:
    $key_6d98 = { 3e f7 [2] 1a f9 [2] 31 d5 [2] 1f f7 [2] 0b ec [2] 04 f6 [2] 1a eb [2] 18 ea [2] 03 ec [2] 1f eb [2] 03 c4 }

  condition:
    any of them
}