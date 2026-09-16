rule TTP_XOR_QUAD_CurrentVersionRun_a073 {
  strings:
    $key_a073 = { f3 1c [2] d7 12 [2] fc 3e [2] d2 1c [2] c6 07 [2] c9 1d [2] d7 00 [2] d5 01 [2] ce 07 [2] d2 00 [2] ce 2f }

  condition:
    any of them
}