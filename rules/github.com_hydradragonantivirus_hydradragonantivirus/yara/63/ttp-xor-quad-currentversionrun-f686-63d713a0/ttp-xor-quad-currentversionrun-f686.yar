rule TTP_XOR_QUAD_CurrentVersionRun_f686 {
  strings:
    $key_f686 = { a5 e9 [2] 81 e7 [2] aa cb [2] 84 e9 [2] 90 f2 [2] 9f e8 [2] 81 f5 [2] 83 f4 [2] 98 f2 [2] 84 f5 [2] 98 da }

  condition:
    any of them
}