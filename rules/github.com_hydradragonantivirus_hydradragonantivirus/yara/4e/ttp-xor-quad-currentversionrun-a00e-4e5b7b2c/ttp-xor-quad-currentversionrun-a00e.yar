rule TTP_XOR_QUAD_CurrentVersionRun_a00e {
  strings:
    $key_a00e = { f3 61 [2] d7 6f [2] fc 43 [2] d2 61 [2] c6 7a [2] c9 60 [2] d7 7d [2] d5 7c [2] ce 7a [2] d2 7d [2] ce 52 }

  condition:
    any of them
}