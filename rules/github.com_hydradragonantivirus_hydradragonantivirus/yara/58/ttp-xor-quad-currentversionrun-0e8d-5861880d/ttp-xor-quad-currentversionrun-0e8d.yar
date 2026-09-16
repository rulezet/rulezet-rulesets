rule TTP_XOR_QUAD_CurrentVersionRun_0e8d {
  strings:
    $key_0e8d = { 5d e2 [2] 79 ec [2] 52 c0 [2] 7c e2 [2] 68 f9 [2] 67 e3 [2] 79 fe [2] 7b ff [2] 60 f9 [2] 7c fe [2] 60 d1 }

  condition:
    any of them
}