rule TTP_XOR_QUAD_CurrentVersionRun_b49d {
  strings:
    $key_b49d = { e7 f2 [2] c3 fc [2] e8 d0 [2] c6 f2 [2] d2 e9 [2] dd f3 [2] c3 ee [2] c1 ef [2] da e9 [2] c6 ee [2] da c1 }

  condition:
    any of them
}