rule TTP_XOR_QUAD_CurrentVersionRun_159d {
  strings:
    $key_159d = { 46 f2 [2] 62 fc [2] 49 d0 [2] 67 f2 [2] 73 e9 [2] 7c f3 [2] 62 ee [2] 60 ef [2] 7b e9 [2] 67 ee [2] 7b c1 }

  condition:
    any of them
}