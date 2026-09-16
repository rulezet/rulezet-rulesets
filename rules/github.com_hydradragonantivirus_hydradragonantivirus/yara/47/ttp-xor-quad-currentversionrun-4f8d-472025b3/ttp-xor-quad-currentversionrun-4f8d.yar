rule TTP_XOR_QUAD_CurrentVersionRun_4f8d {
  strings:
    $key_4f8d = { 1c e2 [2] 38 ec [2] 13 c0 [2] 3d e2 [2] 29 f9 [2] 26 e3 [2] 38 fe [2] 3a ff [2] 21 f9 [2] 3d fe [2] 21 d1 }

  condition:
    any of them
}