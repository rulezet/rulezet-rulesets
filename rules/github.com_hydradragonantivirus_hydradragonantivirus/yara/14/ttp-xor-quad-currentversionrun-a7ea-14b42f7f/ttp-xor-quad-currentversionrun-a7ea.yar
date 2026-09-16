rule TTP_XOR_QUAD_CurrentVersionRun_a7ea {
  strings:
    $key_a7ea = { f4 85 [2] d0 8b [2] fb a7 [2] d5 85 [2] c1 9e [2] ce 84 [2] d0 99 [2] d2 98 [2] c9 9e [2] d5 99 [2] c9 b6 }

  condition:
    any of them
}