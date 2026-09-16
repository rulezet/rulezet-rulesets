rule TTP_XOR_QUAD_CurrentVersionRun_5a99 {
  strings:
    $key_5a99 = { 09 f6 [2] 2d f8 [2] 06 d4 [2] 28 f6 [2] 3c ed [2] 33 f7 [2] 2d ea [2] 2f eb [2] 34 ed [2] 28 ea [2] 34 c5 }

  condition:
    any of them
}