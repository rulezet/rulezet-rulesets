rule TTP_XOR_QUAD_CurrentVersionRun_429d {
  strings:
    $key_429d = { 11 f2 [2] 35 fc [2] 1e d0 [2] 30 f2 [2] 24 e9 [2] 2b f3 [2] 35 ee [2] 37 ef [2] 2c e9 [2] 30 ee [2] 2c c1 }

  condition:
    any of them
}