rule TTP_XOR_QUAD_CurrentVersionRun_7e9d {
  strings:
    $key_7e9d = { 2d f2 [2] 09 fc [2] 22 d0 [2] 0c f2 [2] 18 e9 [2] 17 f3 [2] 09 ee [2] 0b ef [2] 10 e9 [2] 0c ee [2] 10 c1 }

  condition:
    any of them
}