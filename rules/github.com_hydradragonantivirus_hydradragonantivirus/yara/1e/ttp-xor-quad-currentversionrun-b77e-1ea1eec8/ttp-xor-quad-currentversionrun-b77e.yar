rule TTP_XOR_QUAD_CurrentVersionRun_b77e {
  strings:
    $key_b77e = { e4 11 [2] c0 1f [2] eb 33 [2] c5 11 [2] d1 0a [2] de 10 [2] c0 0d [2] c2 0c [2] d9 0a [2] c5 0d [2] d9 22 }

  condition:
    any of them
}