rule TTP_XOR_QUAD_CurrentVersionRun_3d84 {
  strings:
    $key_3d84 = { 6e eb [2] 4a e5 [2] 61 c9 [2] 4f eb [2] 5b f0 [2] 54 ea [2] 4a f7 [2] 48 f6 [2] 53 f0 [2] 4f f7 [2] 53 d8 }

  condition:
    any of them
}