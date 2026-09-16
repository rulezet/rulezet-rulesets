rule TTP_XOR_QUAD_CurrentVersionRun_b7ff {
  strings:
    $key_b7ff = { e4 90 [2] c0 9e [2] eb b2 [2] c5 90 [2] d1 8b [2] de 91 [2] c0 8c [2] c2 8d [2] d9 8b [2] c5 8c [2] d9 a3 }

  condition:
    any of them
}