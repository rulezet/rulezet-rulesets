rule TTP_XOR_QUAD_CurrentVersionRun_709d {
  strings:
    $key_709d = { 23 f2 [2] 07 fc [2] 2c d0 [2] 02 f2 [2] 16 e9 [2] 19 f3 [2] 07 ee [2] 05 ef [2] 1e e9 [2] 02 ee [2] 1e c1 }

  condition:
    any of them
}