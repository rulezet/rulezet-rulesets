rule TTP_XOR_QUAD_CurrentVersionRun_f498 {
  strings:
    $key_f498 = { a7 f7 [2] 83 f9 [2] a8 d5 [2] 86 f7 [2] 92 ec [2] 9d f6 [2] 83 eb [2] 81 ea [2] 9a ec [2] 86 eb [2] 9a c4 }

  condition:
    any of them
}