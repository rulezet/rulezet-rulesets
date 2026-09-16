rule TTP_XOR_QUAD_CurrentVersionRun_479d {
  strings:
    $key_479d = { 14 f2 [2] 30 fc [2] 1b d0 [2] 35 f2 [2] 21 e9 [2] 2e f3 [2] 30 ee [2] 32 ef [2] 29 e9 [2] 35 ee [2] 29 c1 }

  condition:
    any of them
}