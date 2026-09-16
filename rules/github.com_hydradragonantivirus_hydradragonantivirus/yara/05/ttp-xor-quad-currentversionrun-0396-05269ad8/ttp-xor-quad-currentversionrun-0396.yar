rule TTP_XOR_QUAD_CurrentVersionRun_0396 {
  strings:
    $key_0396 = { 50 f9 [2] 74 f7 [2] 5f db [2] 71 f9 [2] 65 e2 [2] 6a f8 [2] 74 e5 [2] 76 e4 [2] 6d e2 [2] 71 e5 [2] 6d ca }

  condition:
    any of them
}