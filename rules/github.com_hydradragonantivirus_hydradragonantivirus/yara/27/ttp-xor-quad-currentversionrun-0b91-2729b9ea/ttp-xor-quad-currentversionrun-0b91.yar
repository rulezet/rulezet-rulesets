rule TTP_XOR_QUAD_CurrentVersionRun_0b91 {
  strings:
    $key_0b91 = { 58 fe [2] 7c f0 [2] 57 dc [2] 79 fe [2] 6d e5 [2] 62 ff [2] 7c e2 [2] 7e e3 [2] 65 e5 [2] 79 e2 [2] 65 cd }

  condition:
    any of them
}