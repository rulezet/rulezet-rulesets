rule TTP_XOR_QUAD_CurrentVersionRun_329d {
  strings:
    $key_329d = { 61 f2 [2] 45 fc [2] 6e d0 [2] 40 f2 [2] 54 e9 [2] 5b f3 [2] 45 ee [2] 47 ef [2] 5c e9 [2] 40 ee [2] 5c c1 }

  condition:
    any of them
}