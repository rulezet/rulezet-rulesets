rule TTP_XOR_QUAD_CurrentVersionRun_4e9d {
  strings:
    $key_4e9d = { 1d f2 [2] 39 fc [2] 12 d0 [2] 3c f2 [2] 28 e9 [2] 27 f3 [2] 39 ee [2] 3b ef [2] 20 e9 [2] 3c ee [2] 20 c1 }

  condition:
    any of them
}