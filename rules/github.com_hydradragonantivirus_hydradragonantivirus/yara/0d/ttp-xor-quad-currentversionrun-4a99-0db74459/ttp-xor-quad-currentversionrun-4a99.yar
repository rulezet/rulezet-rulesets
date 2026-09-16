rule TTP_XOR_QUAD_CurrentVersionRun_4a99 {
  strings:
    $key_4a99 = { 19 f6 [2] 3d f8 [2] 16 d4 [2] 38 f6 [2] 2c ed [2] 23 f7 [2] 3d ea [2] 3f eb [2] 24 ed [2] 38 ea [2] 24 c5 }

  condition:
    any of them
}