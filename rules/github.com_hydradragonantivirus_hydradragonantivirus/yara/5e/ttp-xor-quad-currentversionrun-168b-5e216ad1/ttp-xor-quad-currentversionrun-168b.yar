rule TTP_XOR_QUAD_CurrentVersionRun_168b {
  strings:
    $key_168b = { 45 e4 [2] 61 ea [2] 4a c6 [2] 64 e4 [2] 70 ff [2] 7f e5 [2] 61 f8 [2] 63 f9 [2] 78 ff [2] 64 f8 [2] 78 d7 }

  condition:
    any of them
}