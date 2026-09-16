rule TTP_XOR_QUAD_CurrentVersionRun_7798 {
  strings:
    $key_7798 = { 24 f7 [2] 00 f9 [2] 2b d5 [2] 05 f7 [2] 11 ec [2] 1e f6 [2] 00 eb [2] 02 ea [2] 19 ec [2] 05 eb [2] 19 c4 }

  condition:
    any of them
}