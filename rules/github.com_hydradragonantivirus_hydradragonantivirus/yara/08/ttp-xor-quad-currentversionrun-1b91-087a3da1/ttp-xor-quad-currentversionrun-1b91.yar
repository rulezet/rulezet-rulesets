rule TTP_XOR_QUAD_CurrentVersionRun_1b91 {
  strings:
    $key_1b91 = { 48 fe [2] 6c f0 [2] 47 dc [2] 69 fe [2] 7d e5 [2] 72 ff [2] 6c e2 [2] 6e e3 [2] 75 e5 [2] 69 e2 [2] 75 cd }

  condition:
    any of them
}