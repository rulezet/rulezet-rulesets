rule TTP_XOR_QUAD_CurrentVersionRun_7098 {
  strings:
    $key_7098 = { 23 f7 [2] 07 f9 [2] 2c d5 [2] 02 f7 [2] 16 ec [2] 19 f6 [2] 07 eb [2] 05 ea [2] 1e ec [2] 02 eb [2] 1e c4 }

  condition:
    any of them
}