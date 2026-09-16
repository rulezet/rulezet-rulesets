rule TTP_XOR_QUAD_CurrentVersionRun_a0f5 {
  strings:
    $key_a0f5 = { f3 9a [2] d7 94 [2] fc b8 [2] d2 9a [2] c6 81 [2] c9 9b [2] d7 86 [2] d5 87 [2] ce 81 [2] d2 86 [2] ce a9 }

  condition:
    any of them
}