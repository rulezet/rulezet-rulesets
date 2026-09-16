rule TTP_XOR_QUAD_CurrentVersionRun_b62e {
  strings:
    $key_b62e = { e5 41 [2] c1 4f [2] ea 63 [2] c4 41 [2] d0 5a [2] df 40 [2] c1 5d [2] c3 5c [2] d8 5a [2] c4 5d [2] d8 72 }

  condition:
    any of them
}