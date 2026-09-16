rule TTP_XOR_QUAD_CurrentVersionRun_3f8d {
  strings:
    $key_3f8d = { 6c e2 [2] 48 ec [2] 63 c0 [2] 4d e2 [2] 59 f9 [2] 56 e3 [2] 48 fe [2] 4a ff [2] 51 f9 [2] 4d fe [2] 51 d1 }

  condition:
    any of them
}