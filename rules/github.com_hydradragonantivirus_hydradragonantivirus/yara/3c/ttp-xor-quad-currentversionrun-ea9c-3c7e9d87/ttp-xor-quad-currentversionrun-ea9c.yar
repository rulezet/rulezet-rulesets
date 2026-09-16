rule TTP_XOR_QUAD_CurrentVersionRun_ea9c {
  strings:
    $key_ea9c = { b9 f3 [2] 9d fd [2] b6 d1 [2] 98 f3 [2] 8c e8 [2] 83 f2 [2] 9d ef [2] 9f ee [2] 84 e8 [2] 98 ef [2] 84 c0 }

  condition:
    any of them
}