rule TTP_XOR_QUAD_CurrentVersionRun_3b91 {
  strings:
    $key_3b91 = { 68 fe [2] 4c f0 [2] 67 dc [2] 49 fe [2] 5d e5 [2] 52 ff [2] 4c e2 [2] 4e e3 [2] 55 e5 [2] 49 e2 [2] 55 cd }

  condition:
    any of them
}