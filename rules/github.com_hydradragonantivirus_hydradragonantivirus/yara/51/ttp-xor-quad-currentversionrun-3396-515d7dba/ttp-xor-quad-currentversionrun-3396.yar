rule TTP_XOR_QUAD_CurrentVersionRun_3396 {
  strings:
    $key_3396 = { 60 f9 [2] 44 f7 [2] 6f db [2] 41 f9 [2] 55 e2 [2] 5a f8 [2] 44 e5 [2] 46 e4 [2] 5d e2 [2] 41 e5 [2] 5d ca }

  condition:
    any of them
}