rule TTP_XOR_QUAD_CurrentVersionRun_6e8d {
  strings:
    $key_6e8d = { 3d e2 [2] 19 ec [2] 32 c0 [2] 1c e2 [2] 08 f9 [2] 07 e3 [2] 19 fe [2] 1b ff [2] 00 f9 [2] 1c fe [2] 00 d1 }

  condition:
    any of them
}