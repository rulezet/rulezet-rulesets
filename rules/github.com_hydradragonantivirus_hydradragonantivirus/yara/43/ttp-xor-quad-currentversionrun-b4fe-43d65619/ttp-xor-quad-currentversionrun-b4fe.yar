rule TTP_XOR_QUAD_CurrentVersionRun_b4fe {
  strings:
    $key_b4fe = { e7 91 [2] c3 9f [2] e8 b3 [2] c6 91 [2] d2 8a [2] dd 90 [2] c3 8d [2] c1 8c [2] da 8a [2] c6 8d [2] da a2 }

  condition:
    any of them
}