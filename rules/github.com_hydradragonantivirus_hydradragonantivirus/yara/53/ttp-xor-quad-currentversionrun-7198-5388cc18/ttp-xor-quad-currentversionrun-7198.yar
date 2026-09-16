rule TTP_XOR_QUAD_CurrentVersionRun_7198 {
  strings:
    $key_7198 = { 22 f7 [2] 06 f9 [2] 2d d5 [2] 03 f7 [2] 17 ec [2] 18 f6 [2] 06 eb [2] 04 ea [2] 1f ec [2] 03 eb [2] 1f c4 }

  condition:
    any of them
}