rule TTP_XOR_QUAD_CurrentVersionRun_318d {
  strings:
    $key_318d = { 62 e2 [2] 46 ec [2] 6d c0 [2] 43 e2 [2] 57 f9 [2] 58 e3 [2] 46 fe [2] 44 ff [2] 5f f9 [2] 43 fe [2] 5f d1 }

  condition:
    any of them
}