rule TTP_XOR_QUAD_CurrentVersionRun_0686 {
  strings:
    $key_0686 = { 55 e9 [2] 71 e7 [2] 5a cb [2] 74 e9 [2] 60 f2 [2] 6f e8 [2] 71 f5 [2] 73 f4 [2] 68 f2 [2] 74 f5 [2] 68 da }

  condition:
    any of them
}