rule TTP_XOR_QUAD_CurrentVersionRun_1f9d {
  strings:
    $key_1f9d = { 4c f2 [2] 68 fc [2] 43 d0 [2] 6d f2 [2] 79 e9 [2] 76 f3 [2] 68 ee [2] 6a ef [2] 71 e9 [2] 6d ee [2] 71 c1 }

  condition:
    any of them
}