rule TTP_XOR_QUAD_CurrentVersionRun_e39d {
  strings:
    $key_e39d = { b0 f2 [2] 94 fc [2] bf d0 [2] 91 f2 [2] 85 e9 [2] 8a f3 [2] 94 ee [2] 96 ef [2] 8d e9 [2] 91 ee [2] 8d c1 }

  condition:
    any of them
}