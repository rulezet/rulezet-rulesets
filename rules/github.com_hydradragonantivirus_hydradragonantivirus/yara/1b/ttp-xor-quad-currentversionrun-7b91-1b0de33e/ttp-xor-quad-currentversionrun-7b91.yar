rule TTP_XOR_QUAD_CurrentVersionRun_7b91 {
  strings:
    $key_7b91 = { 28 fe [2] 0c f0 [2] 27 dc [2] 09 fe [2] 1d e5 [2] 12 ff [2] 0c e2 [2] 0e e3 [2] 15 e5 [2] 09 e2 [2] 15 cd }

  condition:
    any of them
}