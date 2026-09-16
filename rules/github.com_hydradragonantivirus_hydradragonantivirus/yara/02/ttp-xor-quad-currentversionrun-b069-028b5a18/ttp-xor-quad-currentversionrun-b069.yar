rule TTP_XOR_QUAD_CurrentVersionRun_b069 {
  strings:
    $key_b069 = { e3 06 [2] c7 08 [2] ec 24 [2] c2 06 [2] d6 1d [2] d9 07 [2] c7 1a [2] c5 1b [2] de 1d [2] c2 1a [2] de 35 }

  condition:
    any of them
}