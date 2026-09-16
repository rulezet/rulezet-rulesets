rule TTP_XOR_QUAD_CurrentVersionRun_ef97 {
  strings:
    $key_ef97 = { bc f8 [2] 98 f6 [2] b3 da [2] 9d f8 [2] 89 e3 [2] 86 f9 [2] 98 e4 [2] 9a e5 [2] 81 e3 [2] 9d e4 [2] 81 cb }

  condition:
    any of them
}