rule TTP_XOR_QUAD_CurrentVersionRun_b71f {
  strings:
    $key_b71f = { e4 70 [2] c0 7e [2] eb 52 [2] c5 70 [2] d1 6b [2] de 71 [2] c0 6c [2] c2 6d [2] d9 6b [2] c5 6c [2] d9 43 }

  condition:
    any of them
}