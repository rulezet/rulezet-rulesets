rule TTP_XOR_QUAD_CurrentVersionRun_1d84 {
  strings:
    $key_1d84 = { 4e eb [2] 6a e5 [2] 41 c9 [2] 6f eb [2] 7b f0 [2] 74 ea [2] 6a f7 [2] 68 f6 [2] 73 f0 [2] 6f f7 [2] 73 d8 }

  condition:
    any of them
}