rule TTP_XOR_QUAD_CurrentVersionRun_a023 {
  strings:
    $key_a023 = { f3 4c [2] d7 42 [2] fc 6e [2] d2 4c [2] c6 57 [2] c9 4d [2] d7 50 [2] d5 51 [2] ce 57 [2] d2 50 [2] ce 7f }

  condition:
    any of them
}