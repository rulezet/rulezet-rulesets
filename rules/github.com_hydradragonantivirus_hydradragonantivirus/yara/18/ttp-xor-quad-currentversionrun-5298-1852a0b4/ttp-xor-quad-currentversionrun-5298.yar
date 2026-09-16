rule TTP_XOR_QUAD_CurrentVersionRun_5298 {
  strings:
    $key_5298 = { 01 f7 [2] 25 f9 [2] 0e d5 [2] 20 f7 [2] 34 ec [2] 3b f6 [2] 25 eb [2] 27 ea [2] 3c ec [2] 20 eb [2] 3c c4 }

  condition:
    any of them
}