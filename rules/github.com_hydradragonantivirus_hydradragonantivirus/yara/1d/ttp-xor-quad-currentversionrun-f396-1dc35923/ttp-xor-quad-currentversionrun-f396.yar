rule TTP_XOR_QUAD_CurrentVersionRun_f396 {
  strings:
    $key_f396 = { a0 f9 [2] 84 f7 [2] af db [2] 81 f9 [2] 95 e2 [2] 9a f8 [2] 84 e5 [2] 86 e4 [2] 9d e2 [2] 81 e5 [2] 9d ca }

  condition:
    any of them
}