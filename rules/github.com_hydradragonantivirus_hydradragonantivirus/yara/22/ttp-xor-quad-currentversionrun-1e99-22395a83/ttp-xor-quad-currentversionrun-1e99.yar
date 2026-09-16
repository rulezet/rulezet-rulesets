rule TTP_XOR_QUAD_CurrentVersionRun_1e99 {
  strings:
    $key_1e99 = { 4d f6 [2] 69 f8 [2] 42 d4 [2] 6c f6 [2] 78 ed [2] 77 f7 [2] 69 ea [2] 6b eb [2] 70 ed [2] 6c ea [2] 70 c5 }

  condition:
    any of them
}