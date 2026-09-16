rule TTP_XOR_QUAD_CurrentVersionRun_609d {
  strings:
    $key_609d = { 33 f2 [2] 17 fc [2] 3c d0 [2] 12 f2 [2] 06 e9 [2] 09 f3 [2] 17 ee [2] 15 ef [2] 0e e9 [2] 12 ee [2] 0e c1 }

  condition:
    any of them
}