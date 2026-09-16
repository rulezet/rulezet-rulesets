rule TTP_XOR_QUAD_CurrentVersionRun_728d {
  strings:
    $key_728d = { 21 e2 [2] 05 ec [2] 2e c0 [2] 00 e2 [2] 14 f9 [2] 1b e3 [2] 05 fe [2] 07 ff [2] 1c f9 [2] 00 fe [2] 1c d1 }

  condition:
    any of them
}