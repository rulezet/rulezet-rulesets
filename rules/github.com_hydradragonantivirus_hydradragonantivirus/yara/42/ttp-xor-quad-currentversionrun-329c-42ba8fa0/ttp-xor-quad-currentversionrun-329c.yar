rule TTP_XOR_QUAD_CurrentVersionRun_329c {
  strings:
    $key_329c = { 61 f3 [2] 45 fd [2] 6e d1 [2] 40 f3 [2] 54 e8 [2] 5b f2 [2] 45 ef [2] 47 ee [2] 5c e8 [2] 40 ef [2] 5c c0 }

  condition:
    any of them
}