rule TTP_XOR_QUAD_CurrentVersionRun_7d84 {
  strings:
    $key_7d84 = { 2e eb [2] 0a e5 [2] 21 c9 [2] 0f eb [2] 1b f0 [2] 14 ea [2] 0a f7 [2] 08 f6 [2] 13 f0 [2] 0f f7 [2] 13 d8 }

  condition:
    any of them
}