rule TTP_XOR_QUAD_CurrentVersionRun_fc9d {
  strings:
    $key_fc9d = { af f2 [2] 8b fc [2] a0 d0 [2] 8e f2 [2] 9a e9 [2] 95 f3 [2] 8b ee [2] 89 ef [2] 92 e9 [2] 8e ee [2] 92 c1 }

  condition:
    any of them
}