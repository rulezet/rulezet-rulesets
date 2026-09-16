rule TTP_XOR_QUAD_CurrentVersionRun_a7f4 {
  strings:
    $key_a7f4 = { f4 9b [2] d0 95 [2] fb b9 [2] d5 9b [2] c1 80 [2] ce 9a [2] d0 87 [2] d2 86 [2] c9 80 [2] d5 87 [2] c9 a8 }

  condition:
    any of them
}