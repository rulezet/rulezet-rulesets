rule TTP_XOR_QUAD_CurrentVersionRun_7e99 {
  strings:
    $key_7e99 = { 2d f6 [2] 09 f8 [2] 22 d4 [2] 0c f6 [2] 18 ed [2] 17 f7 [2] 09 ea [2] 0b eb [2] 10 ed [2] 0c ea [2] 10 c5 }

  condition:
    any of them
}