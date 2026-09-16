rule TTP_XOR_QUAD_CurrentVersionRun_289c {
  strings:
    $key_289c = { 7b f3 [2] 5f fd [2] 74 d1 [2] 5a f3 [2] 4e e8 [2] 41 f2 [2] 5f ef [2] 5d ee [2] 46 e8 [2] 5a ef [2] 46 c0 }

  condition:
    any of them
}