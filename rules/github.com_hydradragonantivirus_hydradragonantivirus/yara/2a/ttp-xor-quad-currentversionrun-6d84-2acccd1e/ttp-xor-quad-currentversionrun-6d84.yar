rule TTP_XOR_QUAD_CurrentVersionRun_6d84 {
  strings:
    $key_6d84 = { 3e eb [2] 1a e5 [2] 31 c9 [2] 1f eb [2] 0b f0 [2] 04 ea [2] 1a f7 [2] 18 f6 [2] 03 f0 [2] 1f f7 [2] 03 d8 }

  condition:
    any of them
}