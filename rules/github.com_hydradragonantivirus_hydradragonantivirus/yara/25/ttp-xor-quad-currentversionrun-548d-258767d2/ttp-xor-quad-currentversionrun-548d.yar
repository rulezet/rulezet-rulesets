rule TTP_XOR_QUAD_CurrentVersionRun_548d {
  strings:
    $key_548d = { 07 e2 [2] 23 ec [2] 08 c0 [2] 26 e2 [2] 32 f9 [2] 3d e3 [2] 23 fe [2] 21 ff [2] 3a f9 [2] 26 fe [2] 3a d1 }

  condition:
    any of them
}