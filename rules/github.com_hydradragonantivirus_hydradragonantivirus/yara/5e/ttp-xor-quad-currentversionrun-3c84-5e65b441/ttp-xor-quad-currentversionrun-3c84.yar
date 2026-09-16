rule TTP_XOR_QUAD_CurrentVersionRun_3c84 {
  strings:
    $key_3c84 = { 6f eb [2] 4b e5 [2] 60 c9 [2] 4e eb [2] 5a f0 [2] 55 ea [2] 4b f7 [2] 49 f6 [2] 52 f0 [2] 4e f7 [2] 52 d8 }

  condition:
    any of them
}