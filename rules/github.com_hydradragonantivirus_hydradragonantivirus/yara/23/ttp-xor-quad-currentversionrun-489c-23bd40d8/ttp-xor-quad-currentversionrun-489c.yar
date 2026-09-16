rule TTP_XOR_QUAD_CurrentVersionRun_489c {
  strings:
    $key_489c = { 1b f3 [2] 3f fd [2] 14 d1 [2] 3a f3 [2] 2e e8 [2] 21 f2 [2] 3f ef [2] 3d ee [2] 26 e8 [2] 3a ef [2] 26 c0 }

  condition:
    any of them
}