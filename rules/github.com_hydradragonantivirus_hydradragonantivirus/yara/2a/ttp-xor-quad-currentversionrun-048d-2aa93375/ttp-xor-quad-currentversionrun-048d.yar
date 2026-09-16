rule TTP_XOR_QUAD_CurrentVersionRun_048d {
  strings:
    $key_048d = { 57 e2 [2] 73 ec [2] 58 c0 [2] 76 e2 [2] 62 f9 [2] 6d e3 [2] 73 fe [2] 71 ff [2] 6a f9 [2] 76 fe [2] 6a d1 }

  condition:
    any of them
}