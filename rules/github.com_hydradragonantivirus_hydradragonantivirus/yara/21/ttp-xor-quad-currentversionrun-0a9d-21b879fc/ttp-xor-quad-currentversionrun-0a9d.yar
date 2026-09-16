rule TTP_XOR_QUAD_CurrentVersionRun_0a9d {
  strings:
    $key_0a9d = { 59 f2 [2] 7d fc [2] 56 d0 [2] 78 f2 [2] 6c e9 [2] 63 f3 [2] 7d ee [2] 7f ef [2] 64 e9 [2] 78 ee [2] 64 c1 }

  condition:
    any of them
}