rule TTP_XOR_QUAD_CurrentVersionRun_a7e8 {
  strings:
    $key_a7e8 = { f4 87 [2] d0 89 [2] fb a5 [2] d5 87 [2] c1 9c [2] ce 86 [2] d0 9b [2] d2 9a [2] c9 9c [2] d5 9b [2] c9 b4 }

  condition:
    any of them
}