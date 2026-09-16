rule TTP_XOR_QUAD_CurrentVersionRun_5b91 {
  strings:
    $key_5b91 = { 08 fe [2] 2c f0 [2] 07 dc [2] 29 fe [2] 3d e5 [2] 32 ff [2] 2c e2 [2] 2e e3 [2] 35 e5 [2] 29 e2 [2] 35 cd }

  condition:
    any of them
}