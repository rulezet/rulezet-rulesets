rule TTP_XOR_QUAD_CurrentVersionRun_4b99 {
  strings:
    $key_4b99 = { 18 f6 [2] 3c f8 [2] 17 d4 [2] 39 f6 [2] 2d ed [2] 22 f7 [2] 3c ea [2] 3e eb [2] 25 ed [2] 39 ea [2] 25 c5 }

  condition:
    any of them
}