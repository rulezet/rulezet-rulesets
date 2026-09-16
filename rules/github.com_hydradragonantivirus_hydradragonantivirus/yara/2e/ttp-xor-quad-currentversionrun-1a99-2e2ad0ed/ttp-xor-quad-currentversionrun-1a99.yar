rule TTP_XOR_QUAD_CurrentVersionRun_1a99 {
  strings:
    $key_1a99 = { 49 f6 [2] 6d f8 [2] 46 d4 [2] 68 f6 [2] 7c ed [2] 73 f7 [2] 6d ea [2] 6f eb [2] 74 ed [2] 68 ea [2] 74 c5 }

  condition:
    any of them
}