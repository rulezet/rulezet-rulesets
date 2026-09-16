rule TTP_XOR_QUAD_CurrentVersionRun_109d {
  strings:
    $key_109d = { 43 f2 [2] 67 fc [2] 4c d0 [2] 62 f2 [2] 76 e9 [2] 79 f3 [2] 67 ee [2] 65 ef [2] 7e e9 [2] 62 ee [2] 7e c1 }

  condition:
    any of them
}