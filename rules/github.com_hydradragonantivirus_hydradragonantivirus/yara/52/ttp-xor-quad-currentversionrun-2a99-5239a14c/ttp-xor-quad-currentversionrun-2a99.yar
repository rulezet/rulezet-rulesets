rule TTP_XOR_QUAD_CurrentVersionRun_2a99 {
  strings:
    $key_2a99 = { 79 f6 [2] 5d f8 [2] 76 d4 [2] 58 f6 [2] 4c ed [2] 43 f7 [2] 5d ea [2] 5f eb [2] 44 ed [2] 58 ea [2] 44 c5 }

  condition:
    any of them
}