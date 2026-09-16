rule TTP_XOR_QUAD_CurrentVersionRun_1384 {
  strings:
    $key_1384 = { 40 eb [2] 64 e5 [2] 4f c9 [2] 61 eb [2] 75 f0 [2] 7a ea [2] 64 f7 [2] 66 f6 [2] 7d f0 [2] 61 f7 [2] 7d d8 }

  condition:
    any of them
}