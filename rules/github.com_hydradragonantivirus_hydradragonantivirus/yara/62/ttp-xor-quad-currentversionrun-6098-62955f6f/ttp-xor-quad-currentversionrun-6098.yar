rule TTP_XOR_QUAD_CurrentVersionRun_6098 {
  strings:
    $key_6098 = { 33 f7 [2] 17 f9 [2] 3c d5 [2] 12 f7 [2] 06 ec [2] 09 f6 [2] 17 eb [2] 15 ea [2] 0e ec [2] 12 eb [2] 0e c4 }

  condition:
    any of them
}