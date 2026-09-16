rule TTP_XOR_QUAD_CurrentVersionRun_b12e {
  strings:
    $key_b12e = { e2 41 [2] c6 4f [2] ed 63 [2] c3 41 [2] d7 5a [2] d8 40 [2] c6 5d [2] c4 5c [2] df 5a [2] c3 5d [2] df 72 }

  condition:
    any of them
}