rule TTP_XOR_QUAD_CurrentVersionRun_169a {
  strings:
    $key_169a = { 45 f5 [2] 61 fb [2] 4a d7 [2] 64 f5 [2] 70 ee [2] 7f f4 [2] 61 e9 [2] 63 e8 [2] 78 ee [2] 64 e9 [2] 78 c6 }

  condition:
    any of them
}