rule TTP_XOR_QUAD_CurrentVersionRun_b42e {
  strings:
    $key_b42e = { e7 41 [2] c3 4f [2] e8 63 [2] c6 41 [2] d2 5a [2] dd 40 [2] c3 5d [2] c1 5c [2] da 5a [2] c6 5d [2] da 72 }

  condition:
    any of them
}