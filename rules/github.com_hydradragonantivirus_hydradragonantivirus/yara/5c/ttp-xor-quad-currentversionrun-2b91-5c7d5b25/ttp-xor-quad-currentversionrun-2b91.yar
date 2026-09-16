rule TTP_XOR_QUAD_CurrentVersionRun_2b91 {
  strings:
    $key_2b91 = { 78 fe [2] 5c f0 [2] 77 dc [2] 59 fe [2] 4d e5 [2] 42 ff [2] 5c e2 [2] 5e e3 [2] 45 e5 [2] 59 e2 [2] 45 cd }

  condition:
    any of them
}