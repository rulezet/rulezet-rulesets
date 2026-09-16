rule TTP_XOR_QUAD_CurrentVersionRun_618d {
  strings:
    $key_618d = { 32 e2 [2] 16 ec [2] 3d c0 [2] 13 e2 [2] 07 f9 [2] 08 e3 [2] 16 fe [2] 14 ff [2] 0f f9 [2] 13 fe [2] 0f d1 }

  condition:
    any of them
}