rule TTP_XOR_QUAD_CurrentVersionRun_b67e {
  strings:
    $key_b67e = { e5 11 [2] c1 1f [2] ea 33 [2] c4 11 [2] d0 0a [2] df 10 [2] c1 0d [2] c3 0c [2] d8 0a [2] c4 0d [2] d8 22 }

  condition:
    any of them
}