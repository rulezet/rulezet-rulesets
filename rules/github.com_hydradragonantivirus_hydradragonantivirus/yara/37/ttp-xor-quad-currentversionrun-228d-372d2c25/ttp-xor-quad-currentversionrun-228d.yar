rule TTP_XOR_QUAD_CurrentVersionRun_228d {
  strings:
    $key_228d = { 71 e2 [2] 55 ec [2] 7e c0 [2] 50 e2 [2] 44 f9 [2] 4b e3 [2] 55 fe [2] 57 ff [2] 4c f9 [2] 50 fe [2] 4c d1 }

  condition:
    any of them
}