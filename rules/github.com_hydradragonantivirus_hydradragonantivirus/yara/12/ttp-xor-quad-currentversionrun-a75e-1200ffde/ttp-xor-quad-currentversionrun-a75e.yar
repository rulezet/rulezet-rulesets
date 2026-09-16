rule TTP_XOR_QUAD_CurrentVersionRun_a75e {
  strings:
    $key_a75e = { f4 31 [2] d0 3f [2] fb 13 [2] d5 31 [2] c1 2a [2] ce 30 [2] d0 2d [2] d2 2c [2] c9 2a [2] d5 2d [2] c9 02 }

  condition:
    any of them
}