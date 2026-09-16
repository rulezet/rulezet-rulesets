rule TTP_XOR_QUAD_CurrentVersionRun_118d {
  strings:
    $key_118d = { 42 e2 [2] 66 ec [2] 4d c0 [2] 63 e2 [2] 77 f9 [2] 78 e3 [2] 66 fe [2] 64 ff [2] 7f f9 [2] 63 fe [2] 7f d1 }

  condition:
    any of them
}