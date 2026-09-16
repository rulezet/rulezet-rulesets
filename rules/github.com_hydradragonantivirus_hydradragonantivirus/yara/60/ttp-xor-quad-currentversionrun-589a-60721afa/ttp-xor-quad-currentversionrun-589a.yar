rule TTP_XOR_QUAD_CurrentVersionRun_589a {
  strings:
    $key_589a = { 0b f5 [2] 2f fb [2] 04 d7 [2] 2a f5 [2] 3e ee [2] 31 f4 [2] 2f e9 [2] 2d e8 [2] 36 ee [2] 2a e9 [2] 36 c6 }

  condition:
    any of them
}