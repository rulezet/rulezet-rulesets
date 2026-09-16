rule TTP_XOR_QUAD_CurrentVersionRun_b19d {
  strings:
    $key_b19d = { e2 f2 [2] c6 fc [2] ed d0 [2] c3 f2 [2] d7 e9 [2] d8 f3 [2] c6 ee [2] c4 ef [2] df e9 [2] c3 ee [2] df c1 }

  condition:
    any of them
}