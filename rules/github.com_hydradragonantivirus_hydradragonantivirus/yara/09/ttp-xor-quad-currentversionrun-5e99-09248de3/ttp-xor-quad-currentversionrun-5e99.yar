rule TTP_XOR_QUAD_CurrentVersionRun_5e99 {
  strings:
    $key_5e99 = { 0d f6 [2] 29 f8 [2] 02 d4 [2] 2c f6 [2] 38 ed [2] 37 f7 [2] 29 ea [2] 2b eb [2] 30 ed [2] 2c ea [2] 30 c5 }

  condition:
    any of them
}