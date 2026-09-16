rule TTP_XOR_QUAD_CurrentVersionRun_a043 {
  strings:
    $key_a043 = { f3 2c [2] d7 22 [2] fc 0e [2] d2 2c [2] c6 37 [2] c9 2d [2] d7 30 [2] d5 31 [2] ce 37 [2] d2 30 [2] ce 1f }

  condition:
    any of them
}