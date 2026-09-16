rule TTP_XOR_QUAD_CurrentVersionRun_278d {
  strings:
    $key_278d = { 74 e2 [2] 50 ec [2] 7b c0 [2] 55 e2 [2] 41 f9 [2] 4e e3 [2] 50 fe [2] 52 ff [2] 49 f9 [2] 55 fe [2] 49 d1 }

  condition:
    any of them
}