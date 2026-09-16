rule TTP_XOR_QUAD_CurrentVersionRun_a02e {
  strings:
    $key_a02e = { f3 41 [2] d7 4f [2] fc 63 [2] d2 41 [2] c6 5a [2] c9 40 [2] d7 5d [2] d5 5c [2] ce 5a [2] d2 5d [2] ce 72 }

  condition:
    any of them
}