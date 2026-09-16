rule TTP_XOR_QUAD_CurrentVersionRun_189c {
  strings:
    $key_189c = { 4b f3 [2] 6f fd [2] 44 d1 [2] 6a f3 [2] 7e e8 [2] 71 f2 [2] 6f ef [2] 6d ee [2] 76 e8 [2] 6a ef [2] 76 c0 }

  condition:
    any of them
}