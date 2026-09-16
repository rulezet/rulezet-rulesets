rule TTP_XOR_QUAD_CurrentVersionRun_a0f4 {
  strings:
    $key_a0f4 = { f3 9b [2] d7 95 [2] fc b9 [2] d2 9b [2] c6 80 [2] c9 9a [2] d7 87 [2] d5 86 [2] ce 80 [2] d2 87 [2] ce a8 }

  condition:
    any of them
}