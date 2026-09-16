rule TTP_XOR_QUAD_CurrentVersionRun_029d {
  strings:
    $key_029d = { 51 f2 [2] 75 fc [2] 5e d0 [2] 70 f2 [2] 64 e9 [2] 6b f3 [2] 75 ee [2] 77 ef [2] 6c e9 [2] 70 ee [2] 6c c1 }

  condition:
    any of them
}