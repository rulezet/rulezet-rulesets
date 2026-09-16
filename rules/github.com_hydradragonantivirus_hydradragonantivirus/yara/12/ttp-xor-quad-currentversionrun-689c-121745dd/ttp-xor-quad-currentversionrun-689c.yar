rule TTP_XOR_QUAD_CurrentVersionRun_689c {
  strings:
    $key_689c = { 3b f3 [2] 1f fd [2] 34 d1 [2] 1a f3 [2] 0e e8 [2] 01 f2 [2] 1f ef [2] 1d ee [2] 06 e8 [2] 1a ef [2] 06 c0 }

  condition:
    any of them
}