rule TTP_XOR_QUAD_CurrentVersionRun_739a {
  strings:
    $key_739a = { 20 f5 [2] 04 fb [2] 2f d7 [2] 01 f5 [2] 15 ee [2] 1a f4 [2] 04 e9 [2] 06 e8 [2] 1d ee [2] 01 e9 [2] 1d c6 }

  condition:
    any of them
}