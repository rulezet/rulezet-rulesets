rule TTP_XOR_QUAD_CurrentVersionRun_a05d {
  strings:
    $key_a05d = { f3 32 [2] d7 3c [2] fc 10 [2] d2 32 [2] c6 29 [2] c9 33 [2] d7 2e [2] d5 2f [2] ce 29 [2] d2 2e [2] ce 01 }

  condition:
    any of them
}