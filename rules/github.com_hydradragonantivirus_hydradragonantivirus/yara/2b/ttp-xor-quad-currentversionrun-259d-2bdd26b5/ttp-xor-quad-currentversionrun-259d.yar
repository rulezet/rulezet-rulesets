rule TTP_XOR_QUAD_CurrentVersionRun_259d {
  strings:
    $key_259d = { 76 f2 [2] 52 fc [2] 79 d0 [2] 57 f2 [2] 43 e9 [2] 4c f3 [2] 52 ee [2] 50 ef [2] 4b e9 [2] 57 ee [2] 4b c1 }

  condition:
    any of them
}