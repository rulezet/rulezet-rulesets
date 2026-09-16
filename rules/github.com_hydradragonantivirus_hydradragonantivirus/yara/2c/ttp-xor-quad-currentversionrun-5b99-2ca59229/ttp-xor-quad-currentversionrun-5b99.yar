rule TTP_XOR_QUAD_CurrentVersionRun_5b99 {
  strings:
    $key_5b99 = { 08 f6 [2] 2c f8 [2] 07 d4 [2] 29 f6 [2] 3d ed [2] 32 f7 [2] 2c ea [2] 2e eb [2] 35 ed [2] 29 ea [2] 35 c5 }

  condition:
    any of them
}