rule TTP_XOR_QUAD_CurrentVersionRun_368d {
  strings:
    $key_368d = { 65 e2 [2] 41 ec [2] 6a c0 [2] 44 e2 [2] 50 f9 [2] 5f e3 [2] 41 fe [2] 43 ff [2] 58 f9 [2] 44 fe [2] 58 d1 }

  condition:
    any of them
}