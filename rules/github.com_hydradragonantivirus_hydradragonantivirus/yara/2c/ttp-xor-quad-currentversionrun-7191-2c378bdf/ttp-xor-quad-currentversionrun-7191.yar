rule TTP_XOR_QUAD_CurrentVersionRun_7191 {
  strings:
    $key_7191 = { 22 fe [2] 06 f0 [2] 2d dc [2] 03 fe [2] 17 e5 [2] 18 ff [2] 06 e2 [2] 04 e3 [2] 1f e5 [2] 03 e2 [2] 1f cd }

  condition:
    any of them
}