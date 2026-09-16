rule TTP_XOR_QUAD_CurrentVersionRun_1c9a {
  strings:
    $key_1c9a = { 4f f5 [2] 6b fb [2] 40 d7 [2] 6e f5 [2] 7a ee [2] 75 f4 [2] 6b e9 [2] 69 e8 [2] 72 ee [2] 6e e9 [2] 72 c6 }

  condition:
    any of them
}