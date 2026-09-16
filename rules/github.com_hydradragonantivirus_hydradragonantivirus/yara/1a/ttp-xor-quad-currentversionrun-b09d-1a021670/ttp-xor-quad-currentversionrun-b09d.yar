rule TTP_XOR_QUAD_CurrentVersionRun_b09d {
  strings:
    $key_b09d = { e3 f2 [2] c7 fc [2] ec d0 [2] c2 f2 [2] d6 e9 [2] d9 f3 [2] c7 ee [2] c5 ef [2] de e9 [2] c2 ee [2] de c1 }

  condition:
    any of them
}