rule TTP_XOR_QUAD_CurrentVersionRun_5b8c {
  strings:
    $key_5b8c = { 08 e3 [2] 2c ed [2] 07 c1 [2] 29 e3 [2] 3d f8 [2] 32 e2 [2] 2c ff [2] 2e fe [2] 35 f8 [2] 29 ff [2] 35 d0 }

  condition:
    any of them
}