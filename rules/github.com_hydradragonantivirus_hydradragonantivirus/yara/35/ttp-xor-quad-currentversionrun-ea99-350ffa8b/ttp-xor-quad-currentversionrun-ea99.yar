rule TTP_XOR_QUAD_CurrentVersionRun_ea99 {
  strings:
    $key_ea99 = { b9 f6 [2] 9d f8 [2] b6 d4 [2] 98 f6 [2] 8c ed [2] 83 f7 [2] 9d ea [2] 9f eb [2] 84 ed [2] 98 ea [2] 84 c5 }

  condition:
    any of them
}