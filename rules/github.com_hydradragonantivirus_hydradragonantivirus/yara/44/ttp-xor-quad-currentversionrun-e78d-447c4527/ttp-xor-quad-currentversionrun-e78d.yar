rule TTP_XOR_QUAD_CurrentVersionRun_e78d {
  strings:
    $key_e78d = { b4 e2 [2] 90 ec [2] bb c0 [2] 95 e2 [2] 81 f9 [2] 8e e3 [2] 90 fe [2] 92 ff [2] 89 f9 [2] 95 fe [2] 89 d1 }

  condition:
    any of them
}