rule TTP_XOR_QUAD_CurrentVersionRun_6a84 {
  strings:
    $key_6a84 = { 39 eb [2] 1d e5 [2] 36 c9 [2] 18 eb [2] 0c f0 [2] 03 ea [2] 1d f7 [2] 1f f6 [2] 04 f0 [2] 18 f7 [2] 04 d8 }

  condition:
    any of them
}