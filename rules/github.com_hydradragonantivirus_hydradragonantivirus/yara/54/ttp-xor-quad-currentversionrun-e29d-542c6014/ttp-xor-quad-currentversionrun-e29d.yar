rule TTP_XOR_QUAD_CurrentVersionRun_e29d {
  strings:
    $key_e29d = { b1 f2 [2] 95 fc [2] be d0 [2] 90 f2 [2] 84 e9 [2] 8b f3 [2] 95 ee [2] 97 ef [2] 8c e9 [2] 90 ee [2] 8c c1 }

  condition:
    any of them
}