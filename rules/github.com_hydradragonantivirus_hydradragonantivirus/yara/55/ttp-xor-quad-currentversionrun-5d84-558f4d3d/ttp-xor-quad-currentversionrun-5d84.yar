rule TTP_XOR_QUAD_CurrentVersionRun_5d84 {
  strings:
    $key_5d84 = { 0e eb [2] 2a e5 [2] 01 c9 [2] 2f eb [2] 3b f0 [2] 34 ea [2] 2a f7 [2] 28 f6 [2] 33 f0 [2] 2f f7 [2] 33 d8 }

  condition:
    any of them
}