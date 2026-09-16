rule TTP_XOR_QUAD_CurrentVersionRun_ef86 {
  strings:
    $key_ef86 = { bc e9 [2] 98 e7 [2] b3 cb [2] 9d e9 [2] 89 f2 [2] 86 e8 [2] 98 f5 [2] 9a f4 [2] 81 f2 [2] 9d f5 [2] 81 da }

  condition:
    any of them
}