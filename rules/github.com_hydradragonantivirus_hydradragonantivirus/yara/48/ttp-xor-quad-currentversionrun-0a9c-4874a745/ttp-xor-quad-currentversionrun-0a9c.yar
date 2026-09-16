rule TTP_XOR_QUAD_CurrentVersionRun_0a9c {
  strings:
    $key_0a9c = { 59 f3 [2] 7d fd [2] 56 d1 [2] 78 f3 [2] 6c e8 [2] 63 f2 [2] 7d ef [2] 7f ee [2] 64 e8 [2] 78 ef [2] 64 c0 }

  condition:
    any of them
}