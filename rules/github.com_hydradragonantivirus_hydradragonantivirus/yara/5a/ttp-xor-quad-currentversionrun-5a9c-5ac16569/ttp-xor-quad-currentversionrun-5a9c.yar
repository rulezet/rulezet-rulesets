rule TTP_XOR_QUAD_CurrentVersionRun_5a9c {
  strings:
    $key_5a9c = { 09 f3 [2] 2d fd [2] 06 d1 [2] 28 f3 [2] 3c e8 [2] 33 f2 [2] 2d ef [2] 2f ee [2] 34 e8 [2] 28 ef [2] 34 c0 }

  condition:
    any of them
}