rule TTP_XOR_QUAD_CurrentVersionRun_5b8d {
  strings:
    $key_5b8d = { 08 e2 [2] 2c ec [2] 07 c0 [2] 29 e2 [2] 3d f9 [2] 32 e3 [2] 2c fe [2] 2e ff [2] 35 f9 [2] 29 fe [2] 35 d1 }

  condition:
    any of them
}