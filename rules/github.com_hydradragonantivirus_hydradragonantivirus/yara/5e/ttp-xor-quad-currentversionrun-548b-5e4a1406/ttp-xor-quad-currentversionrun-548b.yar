rule TTP_XOR_QUAD_CurrentVersionRun_548b {
  strings:
    $key_548b = { 07 e4 [2] 23 ea [2] 08 c6 [2] 26 e4 [2] 32 ff [2] 3d e5 [2] 23 f8 [2] 21 f9 [2] 3a ff [2] 26 f8 [2] 3a d7 }

  condition:
    any of them
}