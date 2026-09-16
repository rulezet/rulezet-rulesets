rule TTP_XOR_QUAD_CurrentVersionRun_389a {
  strings:
    $key_389a = { 6b f5 [2] 4f fb [2] 64 d7 [2] 4a f5 [2] 5e ee [2] 51 f4 [2] 4f e9 [2] 4d e8 [2] 56 ee [2] 4a e9 [2] 56 c6 }

  condition:
    any of them
}