rule TTP_XOR_QUAD_CurrentVersionRun_0798 {
  strings:
    $key_0798 = { 54 f7 [2] 70 f9 [2] 5b d5 [2] 75 f7 [2] 61 ec [2] 6e f6 [2] 70 eb [2] 72 ea [2] 69 ec [2] 75 eb [2] 69 c4 }

  condition:
    any of them
}