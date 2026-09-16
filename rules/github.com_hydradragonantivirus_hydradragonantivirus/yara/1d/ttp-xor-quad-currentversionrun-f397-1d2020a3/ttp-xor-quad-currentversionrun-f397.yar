rule TTP_XOR_QUAD_CurrentVersionRun_f397 {
  strings:
    $key_f397 = { a0 f8 [2] 84 f6 [2] af da [2] 81 f8 [2] 95 e3 [2] 9a f9 [2] 84 e4 [2] 86 e5 [2] 9d e3 [2] 81 e4 [2] 9d cb }

  condition:
    any of them
}