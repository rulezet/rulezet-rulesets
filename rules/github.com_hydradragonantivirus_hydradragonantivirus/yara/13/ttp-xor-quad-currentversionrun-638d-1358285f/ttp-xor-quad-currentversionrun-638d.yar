rule TTP_XOR_QUAD_CurrentVersionRun_638d {
  strings:
    $key_638d = { 30 e2 [2] 14 ec [2] 3f c0 [2] 11 e2 [2] 05 f9 [2] 0a e3 [2] 14 fe [2] 16 ff [2] 0d f9 [2] 11 fe [2] 0d d1 }

  condition:
    any of them
}