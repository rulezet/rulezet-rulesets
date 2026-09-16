rule TTP_XOR_QUAD_CurrentVersionRun_1a9c {
  strings:
    $key_1a9c = { 49 f3 [2] 6d fd [2] 46 d1 [2] 68 f3 [2] 7c e8 [2] 73 f2 [2] 6d ef [2] 6f ee [2] 74 e8 [2] 68 ef [2] 74 c0 }

  condition:
    any of them
}