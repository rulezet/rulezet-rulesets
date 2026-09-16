rule TTP_XOR_QUAD_CurrentVersionRun_049d {
  strings:
    $key_049d = { 57 f2 [2] 73 fc [2] 58 d0 [2] 76 f2 [2] 62 e9 [2] 6d f3 [2] 73 ee [2] 71 ef [2] 6a e9 [2] 76 ee [2] 6a c1 }

  condition:
    any of them
}