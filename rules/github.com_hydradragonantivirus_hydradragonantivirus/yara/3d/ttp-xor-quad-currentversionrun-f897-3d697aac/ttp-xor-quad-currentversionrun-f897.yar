rule TTP_XOR_QUAD_CurrentVersionRun_f897 {
  strings:
    $key_f897 = { ab f8 [2] 8f f6 [2] a4 da [2] 8a f8 [2] 9e e3 [2] 91 f9 [2] 8f e4 [2] 8d e5 [2] 96 e3 [2] 8a e4 [2] 96 cb }

  condition:
    any of them
}