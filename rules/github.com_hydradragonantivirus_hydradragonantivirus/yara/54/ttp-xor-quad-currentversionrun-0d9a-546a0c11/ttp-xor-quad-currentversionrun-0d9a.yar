rule TTP_XOR_QUAD_CurrentVersionRun_0d9a {
  strings:
    $key_0d9a = { 5e f5 [2] 7a fb [2] 51 d7 [2] 7f f5 [2] 6b ee [2] 64 f4 [2] 7a e9 [2] 78 e8 [2] 63 ee [2] 7f e9 [2] 63 c6 }

  condition:
    any of them
}