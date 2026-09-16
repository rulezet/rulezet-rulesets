rule TTP_XOR_QUAD_CurrentVersionRun_1a9d {
  strings:
    $key_1a9d = { 49 f2 [2] 6d fc [2] 46 d0 [2] 68 f2 [2] 7c e9 [2] 73 f3 [2] 6d ee [2] 6f ef [2] 74 e9 [2] 68 ee [2] 74 c1 }

  condition:
    any of them
}