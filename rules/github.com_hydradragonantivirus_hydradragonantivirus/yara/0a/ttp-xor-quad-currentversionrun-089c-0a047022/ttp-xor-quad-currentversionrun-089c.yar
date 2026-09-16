rule TTP_XOR_QUAD_CurrentVersionRun_089c {
  strings:
    $key_089c = { 5b f3 [2] 7f fd [2] 54 d1 [2] 7a f3 [2] 6e e8 [2] 61 f2 [2] 7f ef [2] 7d ee [2] 66 e8 [2] 7a ef [2] 66 c0 }

  condition:
    any of them
}