rule TTP_XOR_QUAD_CurrentVersionRun_169c {
  strings:
    $key_169c = { 45 f3 [2] 61 fd [2] 4a d1 [2] 64 f3 [2] 70 e8 [2] 7f f2 [2] 61 ef [2] 63 ee [2] 78 e8 [2] 64 ef [2] 78 c0 }

  condition:
    any of them
}