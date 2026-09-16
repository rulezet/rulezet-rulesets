rule TTP_XOR_QUAD_CurrentVersionRun_5198 {
  strings:
    $key_5198 = { 02 f7 [2] 26 f9 [2] 0d d5 [2] 23 f7 [2] 37 ec [2] 38 f6 [2] 26 eb [2] 24 ea [2] 3f ec [2] 23 eb [2] 3f c4 }

  condition:
    any of them
}