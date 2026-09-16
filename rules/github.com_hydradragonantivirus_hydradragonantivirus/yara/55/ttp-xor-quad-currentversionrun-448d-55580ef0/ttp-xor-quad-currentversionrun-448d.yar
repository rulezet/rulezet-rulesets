rule TTP_XOR_QUAD_CurrentVersionRun_448d {
  strings:
    $key_448d = { 17 e2 [2] 33 ec [2] 18 c0 [2] 36 e2 [2] 22 f9 [2] 2d e3 [2] 33 fe [2] 31 ff [2] 2a f9 [2] 36 fe [2] 2a d1 }

  condition:
    any of them
}