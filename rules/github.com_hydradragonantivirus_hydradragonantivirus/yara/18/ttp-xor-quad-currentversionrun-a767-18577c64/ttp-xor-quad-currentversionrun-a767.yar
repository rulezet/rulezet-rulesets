rule TTP_XOR_QUAD_CurrentVersionRun_a767 {
  strings:
    $key_a767 = { f4 08 [2] d0 06 [2] fb 2a [2] d5 08 [2] c1 13 [2] ce 09 [2] d0 14 [2] d2 15 [2] c9 13 [2] d5 14 [2] c9 3b }

  condition:
    any of them
}