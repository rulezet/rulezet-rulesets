rule TTP_XOR_QUAD_CurrentVersionRun_7799 {
  strings:
    $key_7799 = { 24 f6 [2] 00 f8 [2] 2b d4 [2] 05 f6 [2] 11 ed [2] 1e f7 [2] 00 ea [2] 02 eb [2] 19 ed [2] 05 ea [2] 19 c5 }

  condition:
    any of them
}