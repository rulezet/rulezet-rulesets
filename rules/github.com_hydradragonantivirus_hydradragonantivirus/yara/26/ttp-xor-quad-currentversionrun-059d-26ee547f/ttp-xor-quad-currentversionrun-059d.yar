rule TTP_XOR_QUAD_CurrentVersionRun_059d {
  strings:
    $key_059d = { 56 f2 [2] 72 fc [2] 59 d0 [2] 77 f2 [2] 63 e9 [2] 6c f3 [2] 72 ee [2] 70 ef [2] 6b e9 [2] 77 ee [2] 6b c1 }

  condition:
    any of them
}