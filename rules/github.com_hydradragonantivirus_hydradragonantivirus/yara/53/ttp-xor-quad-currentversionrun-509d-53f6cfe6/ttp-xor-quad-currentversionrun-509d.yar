rule TTP_XOR_QUAD_CurrentVersionRun_509d {
  strings:
    $key_509d = { 03 f2 [2] 27 fc [2] 0c d0 [2] 22 f2 [2] 36 e9 [2] 39 f3 [2] 27 ee [2] 25 ef [2] 3e e9 [2] 22 ee [2] 3e c1 }

  condition:
    any of them
}