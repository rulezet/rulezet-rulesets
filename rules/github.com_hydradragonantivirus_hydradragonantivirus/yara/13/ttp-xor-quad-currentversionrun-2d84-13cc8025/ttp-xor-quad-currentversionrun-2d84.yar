rule TTP_XOR_QUAD_CurrentVersionRun_2d84 {
  strings:
    $key_2d84 = { 7e eb [2] 5a e5 [2] 71 c9 [2] 5f eb [2] 4b f0 [2] 44 ea [2] 5a f7 [2] 58 f6 [2] 43 f0 [2] 5f f7 [2] 43 d8 }

  condition:
    any of them
}