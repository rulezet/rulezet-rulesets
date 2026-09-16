rule TTP_XOR_QUAD_CurrentVersionRun_a0fa {
  strings:
    $key_a0fa = { f3 95 [2] d7 9b [2] fc b7 [2] d2 95 [2] c6 8e [2] c9 94 [2] d7 89 [2] d5 88 [2] ce 8e [2] d2 89 [2] ce a6 }

  condition:
    any of them
}