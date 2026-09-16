rule TTP_XOR_QUAD_CurrentVersionRun_778d {
  strings:
    $key_778d = { 24 e2 [2] 00 ec [2] 2b c0 [2] 05 e2 [2] 11 f9 [2] 1e e3 [2] 00 fe [2] 02 ff [2] 19 f9 [2] 05 fe [2] 19 d1 }

  condition:
    any of them
}