rule TTP_XOR_QUAD_CurrentVersionRun_a7eb {
  strings:
    $key_a7eb = { f4 84 [2] d0 8a [2] fb a6 [2] d5 84 [2] c1 9f [2] ce 85 [2] d0 98 [2] d2 99 [2] c9 9f [2] d5 98 [2] c9 b7 }

  condition:
    any of them
}