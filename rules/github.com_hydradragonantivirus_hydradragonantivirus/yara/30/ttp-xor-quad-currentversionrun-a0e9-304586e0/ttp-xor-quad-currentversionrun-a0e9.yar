rule TTP_XOR_QUAD_CurrentVersionRun_a0e9 {
  strings:
    $key_a0e9 = { f3 86 [2] d7 88 [2] fc a4 [2] d2 86 [2] c6 9d [2] c9 87 [2] d7 9a [2] d5 9b [2] ce 9d [2] d2 9a [2] ce b5 }

  condition:
    any of them
}