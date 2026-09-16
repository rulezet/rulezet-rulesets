rule TTP_XOR_QUAD_CurrentVersionRun_518d {
  strings:
    $key_518d = { 02 e2 [2] 26 ec [2] 0d c0 [2] 23 e2 [2] 37 f9 [2] 38 e3 [2] 26 fe [2] 24 ff [2] 3f f9 [2] 23 fe [2] 3f d1 }

  condition:
    any of them
}