rule TTP_XOR_QUAD_CurrentVersionRun_3e9d {
  strings:
    $key_3e9d = { 6d f2 [2] 49 fc [2] 62 d0 [2] 4c f2 [2] 58 e9 [2] 57 f3 [2] 49 ee [2] 4b ef [2] 50 e9 [2] 4c ee [2] 50 c1 }

  condition:
    any of them
}