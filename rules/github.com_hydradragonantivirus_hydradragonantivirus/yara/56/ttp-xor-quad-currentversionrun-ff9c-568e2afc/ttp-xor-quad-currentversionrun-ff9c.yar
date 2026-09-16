rule TTP_XOR_QUAD_CurrentVersionRun_ff9c {
  strings:
    $key_ff9c = { ac f3 [2] 88 fd [2] a3 d1 [2] 8d f3 [2] 99 e8 [2] 96 f2 [2] 88 ef [2] 8a ee [2] 91 e8 [2] 8d ef [2] 91 c0 }

  condition:
    any of them
}