rule TTP_XOR_QUAD_CurrentVersionRun_a050 {
  strings:
    $key_a050 = { f3 3f [2] d7 31 [2] fc 1d [2] d2 3f [2] c6 24 [2] c9 3e [2] d7 23 [2] d5 22 [2] ce 24 [2] d2 23 [2] ce 0c }

  condition:
    any of them
}