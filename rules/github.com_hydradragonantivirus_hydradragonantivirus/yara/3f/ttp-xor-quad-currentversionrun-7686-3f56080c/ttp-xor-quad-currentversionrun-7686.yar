rule TTP_XOR_QUAD_CurrentVersionRun_7686 {
  strings:
    $key_7686 = { 25 e9 [2] 01 e7 [2] 2a cb [2] 04 e9 [2] 10 f2 [2] 1f e8 [2] 01 f5 [2] 03 f4 [2] 18 f2 [2] 04 f5 [2] 18 da }

  condition:
    any of them
}