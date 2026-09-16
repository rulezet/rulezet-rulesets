rule TTP_XOR_QUAD_CurrentVersionRun_b7fe {
  strings:
    $key_b7fe = { e4 91 [2] c0 9f [2] eb b3 [2] c5 91 [2] d1 8a [2] de 90 [2] c0 8d [2] c2 8c [2] d9 8a [2] c5 8d [2] d9 a2 }

  condition:
    any of them
}