rule TTP_XOR_QUAD_CurrentVersionRun_4698 {
  strings:
    $key_4698 = { 15 f7 [2] 31 f9 [2] 1a d5 [2] 34 f7 [2] 20 ec [2] 2f f6 [2] 31 eb [2] 33 ea [2] 28 ec [2] 34 eb [2] 28 c4 }

  condition:
    any of them
}