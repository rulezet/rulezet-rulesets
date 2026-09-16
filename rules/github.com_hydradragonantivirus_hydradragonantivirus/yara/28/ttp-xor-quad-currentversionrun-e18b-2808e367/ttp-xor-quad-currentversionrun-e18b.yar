rule TTP_XOR_QUAD_CurrentVersionRun_e18b {
  strings:
    $key_e18b = { b2 e4 [2] 96 ea [2] bd c6 [2] 93 e4 [2] 87 ff [2] 88 e5 [2] 96 f8 [2] 94 f9 [2] 8f ff [2] 93 f8 [2] 8f d7 }

  condition:
    any of them
}