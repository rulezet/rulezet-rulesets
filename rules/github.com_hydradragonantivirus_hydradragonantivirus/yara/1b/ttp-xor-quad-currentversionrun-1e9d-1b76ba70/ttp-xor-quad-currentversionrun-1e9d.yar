rule TTP_XOR_QUAD_CurrentVersionRun_1e9d {
  strings:
    $key_1e9d = { 4d f2 [2] 69 fc [2] 42 d0 [2] 6c f2 [2] 78 e9 [2] 77 f3 [2] 69 ee [2] 6b ef [2] 70 e9 [2] 6c ee [2] 70 c1 }

  condition:
    any of them
}