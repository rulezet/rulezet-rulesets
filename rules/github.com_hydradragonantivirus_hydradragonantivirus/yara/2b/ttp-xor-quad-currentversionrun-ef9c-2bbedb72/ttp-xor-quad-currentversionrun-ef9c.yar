rule TTP_XOR_QUAD_CurrentVersionRun_ef9c {
  strings:
    $key_ef9c = { bc f3 [2] 98 fd [2] b3 d1 [2] 9d f3 [2] 89 e8 [2] 86 f2 [2] 98 ef [2] 9a ee [2] 81 e8 [2] 9d ef [2] 81 c0 }

  condition:
    any of them
}