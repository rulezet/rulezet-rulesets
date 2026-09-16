rule TTP_XOR_QUAD_CurrentVersionRun_e29c {
  strings:
    $key_e29c = { b1 f3 [2] 95 fd [2] be d1 [2] 90 f3 [2] 84 e8 [2] 8b f2 [2] 95 ef [2] 97 ee [2] 8c e8 [2] 90 ef [2] 8c c0 }

  condition:
    any of them
}