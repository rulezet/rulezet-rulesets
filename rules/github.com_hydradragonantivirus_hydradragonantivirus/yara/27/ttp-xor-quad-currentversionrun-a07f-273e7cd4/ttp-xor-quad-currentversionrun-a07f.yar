rule TTP_XOR_QUAD_CurrentVersionRun_a07f {
  strings:
    $key_a07f = { f3 10 [2] d7 1e [2] fc 32 [2] d2 10 [2] c6 0b [2] c9 11 [2] d7 0c [2] d5 0d [2] ce 0b [2] d2 0c [2] ce 23 }

  condition:
    any of them
}