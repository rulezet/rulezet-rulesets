rule TTP_XOR_QUAD_CurrentVersionRun_6f8d {
  strings:
    $key_6f8d = { 3c e2 [2] 18 ec [2] 33 c0 [2] 1d e2 [2] 09 f9 [2] 06 e3 [2] 18 fe [2] 1a ff [2] 01 f9 [2] 1d fe [2] 01 d1 }

  condition:
    any of them
}