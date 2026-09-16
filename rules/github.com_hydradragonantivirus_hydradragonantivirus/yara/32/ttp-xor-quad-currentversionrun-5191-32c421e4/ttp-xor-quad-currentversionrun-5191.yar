rule TTP_XOR_QUAD_CurrentVersionRun_5191 {
  strings:
    $key_5191 = { 02 fe [2] 26 f0 [2] 0d dc [2] 23 fe [2] 37 e5 [2] 38 ff [2] 26 e2 [2] 24 e3 [2] 3f e5 [2] 23 e2 [2] 3f cd }

  condition:
    any of them
}