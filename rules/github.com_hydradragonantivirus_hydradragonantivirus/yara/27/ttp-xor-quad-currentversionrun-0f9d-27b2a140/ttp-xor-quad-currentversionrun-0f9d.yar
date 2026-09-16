rule TTP_XOR_QUAD_CurrentVersionRun_0f9d {
  strings:
    $key_0f9d = { 5c f2 [2] 78 fc [2] 53 d0 [2] 7d f2 [2] 69 e9 [2] 66 f3 [2] 78 ee [2] 7a ef [2] 61 e9 [2] 7d ee [2] 61 c1 }

  condition:
    any of them
}