rule TTP_XOR_QUAD_CurrentVersionRun_439a {
  strings:
    $key_439a = { 10 f5 [2] 34 fb [2] 1f d7 [2] 31 f5 [2] 25 ee [2] 2a f4 [2] 34 e9 [2] 36 e8 [2] 2d ee [2] 31 e9 [2] 2d c6 }

  condition:
    any of them
}