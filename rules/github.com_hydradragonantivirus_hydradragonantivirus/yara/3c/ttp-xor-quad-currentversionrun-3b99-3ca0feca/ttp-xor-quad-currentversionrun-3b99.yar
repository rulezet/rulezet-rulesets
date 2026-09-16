rule TTP_XOR_QUAD_CurrentVersionRun_3b99 {
  strings:
    $key_3b99 = { 68 f6 [2] 4c f8 [2] 67 d4 [2] 49 f6 [2] 5d ed [2] 52 f7 [2] 4c ea [2] 4e eb [2] 55 ed [2] 49 ea [2] 55 c5 }

  condition:
    any of them
}