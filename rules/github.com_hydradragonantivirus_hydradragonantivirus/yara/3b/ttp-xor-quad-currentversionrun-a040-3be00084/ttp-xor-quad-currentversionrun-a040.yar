rule TTP_XOR_QUAD_CurrentVersionRun_a040 {
  strings:
    $key_a040 = { f3 2f [2] d7 21 [2] fc 0d [2] d2 2f [2] c6 34 [2] c9 2e [2] d7 33 [2] d5 32 [2] ce 34 [2] d2 33 [2] ce 1c }

  condition:
    any of them
}