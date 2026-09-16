rule TTP_XOR_QUAD_CurrentVersionRun_7699 {
  strings:
    $key_7699 = { 25 f6 [2] 01 f8 [2] 2a d4 [2] 04 f6 [2] 10 ed [2] 1f f7 [2] 01 ea [2] 03 eb [2] 18 ed [2] 04 ea [2] 18 c5 }

  condition:
    any of them
}