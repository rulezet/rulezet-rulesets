rule TTP_XOR_QUAD_CurrentVersionRun_b66e {
  strings:
    $key_b66e = { e5 01 [2] c1 0f [2] ea 23 [2] c4 01 [2] d0 1a [2] df 00 [2] c1 1d [2] c3 1c [2] d8 1a [2] c4 1d [2] d8 32 }

  condition:
    any of them
}