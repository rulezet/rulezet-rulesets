rule TTP_XOR_QUAD_CurrentVersionRun_149d {
  strings:
    $key_149d = { 47 f2 [2] 63 fc [2] 48 d0 [2] 66 f2 [2] 72 e9 [2] 7d f3 [2] 63 ee [2] 61 ef [2] 7a e9 [2] 66 ee [2] 7a c1 }

  condition:
    any of them
}