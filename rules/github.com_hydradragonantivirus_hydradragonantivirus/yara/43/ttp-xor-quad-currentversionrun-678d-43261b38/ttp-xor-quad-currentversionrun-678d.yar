rule TTP_XOR_QUAD_CurrentVersionRun_678d {
  strings:
    $key_678d = { 34 e2 [2] 10 ec [2] 3b c0 [2] 15 e2 [2] 01 f9 [2] 0e e3 [2] 10 fe [2] 12 ff [2] 09 f9 [2] 15 fe [2] 09 d1 }

  condition:
    any of them
}