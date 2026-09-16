rule TTP_XOR_QUAD_CurrentVersionRun_4f9d {
  strings:
    $key_4f9d = { 1c f2 [2] 38 fc [2] 13 d0 [2] 3d f2 [2] 29 e9 [2] 26 f3 [2] 38 ee [2] 3a ef [2] 21 e9 [2] 3d ee [2] 21 c1 }

  condition:
    any of them
}