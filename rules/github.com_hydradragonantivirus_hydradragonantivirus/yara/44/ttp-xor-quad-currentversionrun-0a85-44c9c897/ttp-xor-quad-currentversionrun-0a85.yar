rule TTP_XOR_QUAD_CurrentVersionRun_0a85 {
  strings:
    $key_0a85 = { 59 ea [2] 7d e4 [2] 56 c8 [2] 78 ea [2] 6c f1 [2] 63 eb [2] 7d f6 [2] 7f f7 [2] 64 f1 [2] 78 f6 [2] 64 d9 }

  condition:
    any of them
}