rule TTP_XOR_QUAD_CurrentVersionRun_6e99 {
  strings:
    $key_6e99 = { 3d f6 [2] 19 f8 [2] 32 d4 [2] 1c f6 [2] 08 ed [2] 07 f7 [2] 19 ea [2] 1b eb [2] 00 ed [2] 1c ea [2] 00 c5 }

  condition:
    any of them
}