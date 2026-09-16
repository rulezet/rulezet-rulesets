rule TTP_XOR_QUAD_CurrentVersionRun_0e9d {
  strings:
    $key_0e9d = { 5d f2 [2] 79 fc [2] 52 d0 [2] 7c f2 [2] 68 e9 [2] 67 f3 [2] 79 ee [2] 7b ef [2] 60 e9 [2] 7c ee [2] 60 c1 }

  condition:
    any of them
}