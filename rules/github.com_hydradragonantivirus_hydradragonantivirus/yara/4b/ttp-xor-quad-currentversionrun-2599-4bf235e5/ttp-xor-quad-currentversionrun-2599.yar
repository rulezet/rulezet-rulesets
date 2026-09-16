rule TTP_XOR_QUAD_CurrentVersionRun_2599 {
  strings:
    $key_2599 = { 76 f6 [2] 52 f8 [2] 79 d4 [2] 57 f6 [2] 43 ed [2] 4c f7 [2] 52 ea [2] 50 eb [2] 4b ed [2] 57 ea [2] 4b c5 }

  condition:
    any of them
}