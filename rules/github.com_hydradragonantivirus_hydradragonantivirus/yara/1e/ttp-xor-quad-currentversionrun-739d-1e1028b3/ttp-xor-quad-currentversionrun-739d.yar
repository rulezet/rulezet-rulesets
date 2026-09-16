rule TTP_XOR_QUAD_CurrentVersionRun_739d {
  strings:
    $key_739d = { 20 f2 [2] 04 fc [2] 2f d0 [2] 01 f2 [2] 15 e9 [2] 1a f3 [2] 04 ee [2] 06 ef [2] 1d e9 [2] 01 ee [2] 1d c1 }

  condition:
    any of them
}