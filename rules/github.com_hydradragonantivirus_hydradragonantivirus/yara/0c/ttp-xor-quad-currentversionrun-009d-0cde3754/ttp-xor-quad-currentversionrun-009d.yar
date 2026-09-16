rule TTP_XOR_QUAD_CurrentVersionRun_009d {
  strings:
    $key_009d = { 53 f2 [2] 77 fc [2] 5c d0 [2] 72 f2 [2] 66 e9 [2] 69 f3 [2] 77 ee [2] 75 ef [2] 6e e9 [2] 72 ee [2] 6e c1 }

  condition:
    any of them
}