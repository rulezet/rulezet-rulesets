rule TTP_XOR_QUAD_CurrentVersionRun_3598 {
  strings:
    $key_3598 = { 66 f7 [2] 42 f9 [2] 69 d5 [2] 47 f7 [2] 53 ec [2] 5c f6 [2] 42 eb [2] 40 ea [2] 5b ec [2] 47 eb [2] 5b c4 }

  condition:
    any of them
}