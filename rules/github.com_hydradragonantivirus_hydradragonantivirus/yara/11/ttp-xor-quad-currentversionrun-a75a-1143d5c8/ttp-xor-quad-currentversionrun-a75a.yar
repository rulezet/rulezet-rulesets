rule TTP_XOR_QUAD_CurrentVersionRun_a75a {
  strings:
    $key_a75a = { f4 35 [2] d0 3b [2] fb 17 [2] d5 35 [2] c1 2e [2] ce 34 [2] d0 29 [2] d2 28 [2] c9 2e [2] d5 29 [2] c9 06 }

  condition:
    any of them
}