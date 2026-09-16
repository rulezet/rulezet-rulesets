rule TTP_XOR_QUAD_CurrentVersionRun_ea9d {
  strings:
    $key_ea9d = { b9 f2 [2] 9d fc [2] b6 d0 [2] 98 f2 [2] 8c e9 [2] 83 f3 [2] 9d ee [2] 9f ef [2] 84 e9 [2] 98 ee [2] 84 c1 }

  condition:
    any of them
}