rule TTP_XOR_QUAD_CurrentVersionRun_5098 {
  strings:
    $key_5098 = { 03 f7 [2] 27 f9 [2] 0c d5 [2] 22 f7 [2] 36 ec [2] 39 f6 [2] 27 eb [2] 25 ea [2] 3e ec [2] 22 eb [2] 3e c4 }

  condition:
    any of them
}