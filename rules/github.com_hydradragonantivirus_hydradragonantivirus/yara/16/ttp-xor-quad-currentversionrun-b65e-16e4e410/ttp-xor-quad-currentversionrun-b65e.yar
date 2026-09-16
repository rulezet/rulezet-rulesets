rule TTP_XOR_QUAD_CurrentVersionRun_b65e {
  strings:
    $key_b65e = { e5 31 [2] c1 3f [2] ea 13 [2] c4 31 [2] d0 2a [2] df 30 [2] c1 2d [2] c3 2c [2] d8 2a [2] c4 2d [2] d8 02 }

  condition:
    any of them
}