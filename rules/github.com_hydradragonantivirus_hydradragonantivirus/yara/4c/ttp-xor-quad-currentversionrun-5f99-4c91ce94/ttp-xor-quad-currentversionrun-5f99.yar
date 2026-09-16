rule TTP_XOR_QUAD_CurrentVersionRun_5f99 {
  strings:
    $key_5f99 = { 0c f6 [2] 28 f8 [2] 03 d4 [2] 2d f6 [2] 39 ed [2] 36 f7 [2] 28 ea [2] 2a eb [2] 31 ed [2] 2d ea [2] 31 c5 }

  condition:
    any of them
}