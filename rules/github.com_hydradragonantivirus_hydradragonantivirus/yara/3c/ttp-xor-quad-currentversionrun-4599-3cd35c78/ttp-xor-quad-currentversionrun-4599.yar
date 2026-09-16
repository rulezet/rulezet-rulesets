rule TTP_XOR_QUAD_CurrentVersionRun_4599 {
  strings:
    $key_4599 = { 16 f6 [2] 32 f8 [2] 19 d4 [2] 37 f6 [2] 23 ed [2] 2c f7 [2] 32 ea [2] 30 eb [2] 2b ed [2] 37 ea [2] 2b c5 }

  condition:
    any of them
}