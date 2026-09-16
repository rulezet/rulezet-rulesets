rule TTP_XOR_QUAD_CurrentVersionRun_a015 {
  strings:
    $key_a015 = { f3 7a [2] d7 74 [2] fc 58 [2] d2 7a [2] c6 61 [2] c9 7b [2] d7 66 [2] d5 67 [2] ce 61 [2] d2 66 [2] ce 49 }

  condition:
    any of them
}