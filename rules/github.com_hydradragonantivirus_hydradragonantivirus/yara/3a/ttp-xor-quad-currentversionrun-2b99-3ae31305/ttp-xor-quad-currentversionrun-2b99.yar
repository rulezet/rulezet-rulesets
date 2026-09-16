rule TTP_XOR_QUAD_CurrentVersionRun_2b99 {
  strings:
    $key_2b99 = { 78 f6 [2] 5c f8 [2] 77 d4 [2] 59 f6 [2] 4d ed [2] 42 f7 [2] 5c ea [2] 5e eb [2] 45 ed [2] 59 ea [2] 45 c5 }

  condition:
    any of them
}