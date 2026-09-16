rule TTP_XOR_QUAD_CurrentVersionRun_a068 {
  strings:
    $key_a068 = { f3 07 [2] d7 09 [2] fc 25 [2] d2 07 [2] c6 1c [2] c9 06 [2] d7 1b [2] d5 1a [2] ce 1c [2] d2 1b [2] ce 34 }

  condition:
    any of them
}