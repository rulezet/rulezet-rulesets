rule TTP_XOR_QUAD_CurrentVersionRun_0598 {
  strings:
    $key_0598 = { 56 f7 [2] 72 f9 [2] 59 d5 [2] 77 f7 [2] 63 ec [2] 6c f6 [2] 72 eb [2] 70 ea [2] 6b ec [2] 77 eb [2] 6b c4 }

  condition:
    any of them
}