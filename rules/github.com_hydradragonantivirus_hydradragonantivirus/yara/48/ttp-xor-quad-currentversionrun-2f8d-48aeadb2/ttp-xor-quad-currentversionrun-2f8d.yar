rule TTP_XOR_QUAD_CurrentVersionRun_2f8d {
  strings:
    $key_2f8d = { 7c e2 [2] 58 ec [2] 73 c0 [2] 5d e2 [2] 49 f9 [2] 46 e3 [2] 58 fe [2] 5a ff [2] 41 f9 [2] 5d fe [2] 41 d1 }

  condition:
    any of them
}