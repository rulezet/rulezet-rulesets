rule TTP_XOR_QUAD_CurrentVersionRun_3f9d {
  strings:
    $key_3f9d = { 6c f2 [2] 48 fc [2] 63 d0 [2] 4d f2 [2] 59 e9 [2] 56 f3 [2] 48 ee [2] 4a ef [2] 51 e9 [2] 4d ee [2] 51 c1 }

  condition:
    any of them
}