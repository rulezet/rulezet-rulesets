rule TTP_XOR_QUAD_CurrentVersionRun_2c84 {
  strings:
    $key_2c84 = { 7f eb [2] 5b e5 [2] 70 c9 [2] 5e eb [2] 4a f0 [2] 45 ea [2] 5b f7 [2] 59 f6 [2] 42 f0 [2] 5e f7 [2] 42 d8 }

  condition:
    any of them
}