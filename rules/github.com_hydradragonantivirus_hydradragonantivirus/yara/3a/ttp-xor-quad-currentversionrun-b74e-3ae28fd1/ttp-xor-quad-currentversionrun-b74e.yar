rule TTP_XOR_QUAD_CurrentVersionRun_b74e {
  strings:
    $key_b74e = { e4 21 [2] c0 2f [2] eb 03 [2] c5 21 [2] d1 3a [2] de 20 [2] c0 3d [2] c2 3c [2] d9 3a [2] c5 3d [2] d9 12 }

  condition:
    any of them
}