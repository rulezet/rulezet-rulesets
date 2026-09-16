rule TTP_XOR_QUAD_CurrentVersionRun_729d {
  strings:
    $key_729d = { 21 f2 [2] 05 fc [2] 2e d0 [2] 00 f2 [2] 14 e9 [2] 1b f3 [2] 05 ee [2] 07 ef [2] 1c e9 [2] 00 ee [2] 1c c1 }

  condition:
    any of them
}