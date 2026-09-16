rule TTP_XOR_QUAD_CurrentVersionRun_209d {
  strings:
    $key_209d = { 73 f2 [2] 57 fc [2] 7c d0 [2] 52 f2 [2] 46 e9 [2] 49 f3 [2] 57 ee [2] 55 ef [2] 4e e9 [2] 52 ee [2] 4e c1 }

  condition:
    any of them
}