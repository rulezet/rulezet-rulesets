rule TTP_XOR_QUAD_CurrentVersionRun_a7fa {
  strings:
    $key_a7fa = { f4 95 [2] d0 9b [2] fb b7 [2] d5 95 [2] c1 8e [2] ce 94 [2] d0 89 [2] d2 88 [2] c9 8e [2] d5 89 [2] c9 a6 }

  condition:
    any of them
}