rule TTP_XOR_QUAD_CurrentVersionRun_3686 {
  strings:
    $key_3686 = { 65 e9 [2] 41 e7 [2] 6a cb [2] 44 e9 [2] 50 f2 [2] 5f e8 [2] 41 f5 [2] 43 f4 [2] 58 f2 [2] 44 f5 [2] 58 da }

  condition:
    any of them
}